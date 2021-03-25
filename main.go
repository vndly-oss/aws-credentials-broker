package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/secure"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/vndly-oss/aws-credentials-broker/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type RoleChoice struct {
	Arn  string `json:"arn"`
	Name string `json:"name"`
}

type IDToken struct {
	Email        string `json:"email"`
	HostedDomain string `json:"hd"`
}

type Account struct {
	Number string       `json:"number"`
	Name   string       `json:"name"`
	Roles  []RoleChoice `json:"roles"`
}

const (
	sessionName         = "aws-broker"
	sessionCallbackName = "aws-broker-cb"
	sessionKey          = "_awscb"
	idKey               = "_awscb_id"
	stateKey            = "_awscb_state"
	callbackKey         = "_awscb_call"
	stateError          = "Unexpected state. Secure session cookies are missing... Please try again."
)

func callback(conf *oauth2.Config, secure bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")

		tok, err := conf.Exchange(utils.NoContext, code)
		if err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		hdFilter := os.Getenv("HOSTED_DOMAIN")
		idTok := tok.Extra("id_token").(string)
		parts := strings.Split(idTok, ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		var idToken IDToken
		if err := json.Unmarshal([]byte(payload), &idToken); err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if hdFilter != "" && hdFilter != idToken.HostedDomain {
			log.Println(fmt.Sprintf("[WARN] - User [%s] of domain [%s] cannot access [%s]", idToken.Email, idToken.HostedDomain, hdFilter))
			c.Redirect(http.StatusTemporaryRedirect, "/forbidden")
			return
		}

		expiresIn := time.Until(tok.Expiry)
		sesh := sessions.DefaultMany(c, sessionName)
		sesh.Set(idKey, idTok)
		sesh.Set(sessionKey, tok.AccessToken)
		sesh.Options(sessions.Options{
			MaxAge:   int(expiresIn.Seconds()) - 300, // Expire 5 minutes before the access token expires
			HttpOnly: true,
			Secure:   secure,
			Path:     "/",
		})
		err = sesh.Save()
		if err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, "/roles")
	}
}

func listRoles(conf *oauth2.Config, ngin *gin.Engine, adminConf *utils.AdminUserConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		sesh := sessions.DefaultMany(c, sessionName)
		seshCallback := sessions.DefaultMany(c, sessionCallbackName)
		accessToken := sesh.Get(sessionKey)
		if accessToken == nil {
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		user, err := utils.GetUserRoles(accessToken.(string), conf, adminConf)
		if err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		var accountQuery string
		var accountName string
		u, err := url.Parse(seshCallback.Get(callbackKey).(string))
		if err == nil {
			accountQuery = u.Query().Get("account")
			accountName = u.Query().Get("accountName")
		}

		accounts := make(map[string]*Account)
		for _, r := range user.Roles.Roles {
			v := strings.Split(r.Value, ",")
			roleArn, providerArn := v[0], v[1]

			accountPattern := regexp.MustCompile(`arn:aws:iam::(\d+):[\w-\/]+`)
			accountNumber := accountPattern.FindStringSubmatch(providerArn)[1]

			if accountQuery != "" && accountQuery != accountNumber {
				continue
			}

			rolePattern := regexp.MustCompile(`arn:aws:iam::\d+:role/([\w-\/]+)`)
			role := rolePattern.FindStringSubmatch(roleArn)[1]
			account := accounts[accountNumber]
			if account == nil {
				account = &Account{
					Name:   accountName,
					Number: accountNumber,
				}
				accounts[accountNumber] = account
			}
			account.Roles = append(account.Roles, RoleChoice{Arn: roleArn, Name: role})
		}

		if len(accounts) == 1 {
			soloRole := ""
			for _, acct := range accounts {
				if len(acct.Roles) == 1 {
					soloRole = acct.Roles[0].Arn
				}
			}

			if soloRole != "" {
				c.Request.URL.Path = "/login"
				c.Request.Method = "POST"

				v := url.Values{}
				v.Set("role", soloRole)
				c.Request.PostForm = v
				ngin.HandleContext(c)
				return
			}
		}

		if len(accounts) == 0 {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"roles_json": gin.H{"error": "No AWS roles mapped to your user account. Contact your GSuite Admin"},
			})
			return
		}

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"roles_json": accounts,
		})
	}
}

func failure(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"roles_json": gin.H{"error": "Failure to obtain AWS credentials. Check the initiating CLI for more information"},
	})
}

func success(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"roles_json": gin.H{"success": true},
	})
}

func login(conf *oauth2.Config, adminConf *utils.AdminUserConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestedRoleArn := c.PostForm("role")

		sesh := sessions.DefaultMany(c, sessionName)
		seshCallback := sessions.DefaultMany(c, sessionCallbackName)
		idToken := sesh.Get(idKey)
		accessToken := sesh.Get(sessionKey)
		if accessToken == nil {
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		user, err := utils.GetUserRoles(accessToken.(string), conf, adminConf)
		if err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		var roleArn, providerArn string
		for _, r := range user.Roles.Roles {
			v := strings.Split(r.Value, ",")
			role, provider := v[0], v[1]
			if role == requestedRoleArn {
				roleArn = role
				providerArn = provider
			}
		}

		if roleArn == "" || providerArn == "" {
			log.Panicf("User cannot assume role %v", requestedRoleArn)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		duration, err := strconv.ParseInt(user.Roles.SessionDuration, 10, 64)
		if err != nil {
			log.Panicf("User cannot assume role %v", requestedRoleArn)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		sess := session.Must(session.NewSession())
		stsService := sts.New(sess)
		resp, err := stsService.AssumeRoleWithWebIdentity(&sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(roleArn),
			RoleSessionName:  aws.String(user.User.Email),
			DurationSeconds:  aws.Int64(duration),
			WebIdentityToken: aws.String(idToken.(string)),
		})
		if err != nil {
			log.Panicf("User cannot assume role %v: %v", requestedRoleArn, err)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		callbackURI := fmt.Sprintf("%v", seshCallback.Get(callbackKey))
		if callbackURI == "<nil>" || callbackURI == "" {
			log.Printf("No callback URI cookie:%v", err)
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"roles_json": gin.H{"error": stateError},
			})
			return
		}

		uri, err := url.Parse(callbackURI)
		if err != nil {
			log.Printf("No callback URI cookie:%v", err)
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"roles_json": gin.H{"error": stateError},
			})
			return
		}

		cred := resp.Credentials
		parameters := url.Values{}
		parameters.Add("access_key_id", *cred.AccessKeyId)
		parameters.Add("secret_access_key", *cred.SecretAccessKey)
		parameters.Add("session_token", *cred.SessionToken)
		uri.RawQuery = parameters.Encode()

		c.Redirect(http.StatusTemporaryRedirect, uri.String())
	}
}

func main() {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_CLIENT_REDIRECT"),
		Scopes: []string{
			"openid",
			"email",
		},
		Endpoint: google.Endpoint,
	}

	pk, err := base64.StdEncoding.DecodeString(os.Getenv("GOOGLE_SA_PK"))
	if err != nil {
		log.Fatal(err)
	}

	adminConf := &utils.AdminUserConfig{
		Email:      os.Getenv("GOOGLE_SA_EMAIL"),
		PrivateKey: pk,
		AdminEmail: os.Getenv("GOOGLE_ADMIN_EMAIL"),
	}

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	pprof.Register(r, nil)

	r.GET("/_internal_/healthcheck", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	secretKey1 := os.Getenv("COOKIE_SECRET_1")
	secretKey2 := os.Getenv("COOKIE_SECRET_2")
	store := cookie.NewStore([]byte(secretKey1), []byte(secretKey2))
	r.Use(sessions.SessionsMany([]string{"aws-broker", "aws-broker-cb"}, store))
	r.Use(static.Serve("/dist", static.LocalFile("./templates", false)))
	r.Use(secure.New(secure.Config{
		IENoOpen:              true,
		FrameDeny:             true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com;",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	allowedOrigin := os.Getenv("ALLOWED_ORIGIN")
	secure := !strings.Contains(allowedOrigin, "localhost")

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{allowedOrigin}
	corsConfig.AllowMethods = []string{"POST"}
	r.Use(cors.New(corsConfig))

	r.LoadHTMLGlob("templates/*.tmpl")

	r.GET("/oauth/google/callback", callback(conf, secure))
	r.GET("/roles", listRoles(conf, r, adminConf))
	r.POST("/login", login(conf, adminConf))
	r.GET("/success", success)
	r.GET("/failure", failure)
	r.GET("/", func(c *gin.Context) {
		sesh := sessions.DefaultMany(c, sessionName)
		seshCallback := sessions.DefaultMany(c, sessionCallbackName)
		callbackURI := c.Query("callback_uri")
		seshCallback.Set(callbackKey, callbackURI)
		seshCallback.Options(sessions.Options{HttpOnly: true, Path: "/"})
		err = seshCallback.Save()
		if err != nil {
			log.Panic(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		tok := sesh.Get(sessionKey)
		if tok == nil {
			// We need to make sure we're only calling loopback addresses as we only want to post to CLIs
			match, _ := regexp.MatchString(`^https?://(127(\.\d+){1,3}|localhost)(:[0-9]+)?.*?$`, callbackURI)
			if !match {
				log.Printf("User didn't provide a loopback address [%s] as the callback uri", callbackURI)
				c.HTML(http.StatusOK, "index.tmpl", gin.H{
					"roles_json": gin.H{"error": "You must provide a loopback address as the callback uri..."},
				})
				return
			}

			state := base64.StdEncoding.EncodeToString(utils.RandToken(32))
			sesh.Set(stateKey, state)
			sesh.Options(sessions.Options{HttpOnly: true, Path: "/"})
			err := sesh.Save()
			if err != nil {
				log.Panic(err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			c.Redirect(http.StatusTemporaryRedirect, conf.AuthCodeURL(state))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, "/roles")
	})

	r.Run(":8234")
}
