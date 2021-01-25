import React from "react";

export const RoleRow = ({ arn, name }) => (
  <div className="role flex-item">
    <input type="radio" name="role" id={arn} value={arn} />
    <label for={arn} className="rb-label">
      {name}
    </label>
  </div>
);

export const AccountRoleGroup = ({ account, children }) => {
  const displayText = account.name === '' ? account.number : `${account.name} (${account.number})`
  return (
    <div className="account flex-item">
      <p style={{ fontSize: "20px" }}>
        Account: {displayText}
      </p>
      <hr />
      <div className="flex-container">{children}</div>
    </div>
  );
};

export const RoleSelectionForm = ({ children }) => (
  <form method="POST" action="/login">
    <p style={{ fontSize: "20px" }}>Select a role:</p>
    <div className="flex-container">{children}</div>
    <div className="flex-container">
      <button className="flex-item signIn" type="submit">
        Sign In
      </button>
    </div>
  </form>
);

export const RoleAssumed = () => (
  <div style={{ textAlign: "center", width: "100%" }}>
    Successfully assumed role! You can close this window now.
  </div>
);

export const Error = ({ message }) => (
  <div>
    <h2>Error:</h2>
    <div className="flex-container">{message}</div>
  </div>
);
