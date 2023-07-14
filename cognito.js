import { poolData } from "./cognito.config.js";
import { 
  CognitoUserPool, CognitoUserAttribute,
	CognitoUser, AuthenticationDetails,
} from 'amazon-cognito-identity-js';

/*
 * Common functions
 */
export function getCognitoUserPool() {
  return new CognitoUserPool(poolData);
}

export function getCurrentCognitoUser() {
  let userPool = getCognitoUserPool();
  return userPool.getCurrentUser();
}

export function getCognitoUser(username) {
  let userPool = getCognitoUserPool();
  return new CognitoUser({Username: username, Pool: userPool});
}

export function getCognitoIdToken(user) {
  return new Promise((resolve) => {
    resolve(user.getSignInUserSession().getIdToken().jwtToken);
  });
}

/*
 * Retrieve users attributes as nominated in cognito (email, username)
 */
export function getUserAttributes(user) {
  return new Promise((resolve, reject) => {
    user.getSession((err) => {
      if (err) { reject(err); return; }
      user.getUserAttributes((err, result) => {
        if (err) { reject(err); return ; }
        try {
          result = result.reduce((map, item) => {map[item.Name] = item.Value; return map;}, {});
          resolve(result);
        } catch (e) {
          reject(e);
        }
      });
    });
  });
}

/*
 * Initiate SignUp workflow
 */
export function signUpCognitoUser(username, password, email) {
  return new Promise((resolve, reject) => {
    let userPool = getCognitoUserPool();
    userPool.signUp(username,
      password,
      [new CognitoUserAttribute({Name: 'email', Value: email})],
      null,
      (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      });
    });
}

/*
 * Initiate SignIn workflow
 */
export function signInCognitoUser(username, password) {
  return new Promise((resolve, reject) => {
    let userPool = getCognitoUserPool();
    let user = new CognitoUser({Username: username, Pool: userPool});
    user.authenticateUser(new AuthenticationDetails({Username: username, Password: password}),
      {
        onSuccess: (response) => { resolve({type: 'onSuccess', response}); },
        onFailure: (e) => { reject(e); },
        newPasswordRequired: (userAttributes, requiredAttributes) => { 
            // User was signed up by an admin and must provide new
            // password and required attributes, if any, to complete
            // authentication.

            // the api doesn't accept this field back
            delete userAttributes.email_verified;
            resolve({type: 'newPasswordRequired', user, userAttributes, requiredAttributes});
        },
      });
  });
}

/*
 * Verify user using a code
 */
export function confirmCognitoUser(username, code) {
  return new Promise((resolve, reject) => {
    let userPool = getCognitoUserPool();
    let user = new CognitoUser({Username: username, Pool: userPool});
    user.confirmRegistration(code, true, 
      (err, result) => {
        if (err) { reject(err); }
        else { resolve(result); }
      }
    );
  });
}

/*
 * handleNewPassword: to be called when a user was signed up by an admin and must provide
 * new password.
 */
export function handleNewPassword(user, userAttributes, newPassword) {
  return new Promise((resolve) => {
    user.completeNewPasswordChallenge(newPassword, userAttributes);
    resolve();
  });
}

/*
 * Verification of user attributes (email address)
 */
export function getAttributeVerificationCode(user, attribute) {
  return new Promise((resolve, reject) => {
    user.getAttributeVerificationCode(attribute,
      {
        onSuccess: (r) => {resolve(r);},
        onFailure: (e) => {reject(e);},
        inputVerificationCode: null,
      });
  });
}

export function verifyAttribute(user, attribute, code) {
  return new Promise((resolve, reject) => {
    user.verifyAttribute(attribute, code,
      {
        onSuccess: (r) => {resolve(r);},
        onFailure: (e) => {reject(e);},
      });
  });
}

/**
 * Forgot password workflow
 */
export function forgotPassword(user) {
  return new Promise((resolve, reject) => {
    user.forgotPassword({
      onSuccess: (r) => {resolve(r);},
      onFailure: (e) => {reject(e);},
      inputVerificationCode: null,
   });
  });
}

export function confirmPassword(user, code, password) {
  return new Promise((resolve, reject) => {
    user.confirmPassword(code, password, {
      onSuccess: (r) => {resolve(r);},
      onFailure: (e) => {reject(e);},
    });
  });
}
