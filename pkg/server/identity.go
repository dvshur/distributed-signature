package server

import (
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/dgrijalva/jwt-go"
)

// IdentityManager ..
type IdentityManager struct {
	cognito *cognitoidentityprovider.CognitoIdentityProvider
}

// NewIdentityManager ..
func NewIdentityManager(c *cognitoidentityprovider.CognitoIdentityProvider) *IdentityManager {
	return &IdentityManager{
		cognito: c,
	}
}

// CheckAuth ..
func (im *IdentityManager) CheckAuth(accessToken string) (bool, error) {
	req := cognitoidentityprovider.GetUserInput{
		AccessToken: &accessToken,
	}

	res, err := im.cognito.GetUser(&req)
	if err != nil {
		return false, err
	}

	if *res.Username != "" {
		return true, nil
	}

	return false, errors.New("Username is empty")
}

// ClientID ..
func (im *IdentityManager) ClientID(req *http.Request) (string, int, error) {
	jwt, err := getJwtTokenFromRequest(req)
	if err != nil {
		return "", http.StatusBadRequest, err
	}

	clientID, err := getJwtClaim(jwt, "sub")
	if err != nil {
		return "", http.StatusBadRequest, err
	}

	if clientID == "" {
		return "", http.StatusBadRequest, errors.New("Sub is empty.")
	}

	authOk, err := im.CheckAuth(jwt)
	if !authOk || err != nil {
		println(authOk, err.Error())
		return "", http.StatusForbidden, errors.New("Authentication failed.")
	}

	return clientID, http.StatusOK, nil
}

func getJwtTokenFromRequest(req *http.Request) (string, error) {
	const bearerToken = "Bearer "

	authorizationHeaderValues := req.Header.Values("Authorization")

	if len(authorizationHeaderValues) == 0 ||
		len(authorizationHeaderValues[0]) < len(bearerToken) ||
		authorizationHeaderValues[0][:len(bearerToken)] != bearerToken {
		return "", errors.New("No access token provided.")
	}

	return authorizationHeaderValues[0][len(bearerToken):], nil
}

func getJwtClaim(jwtRaw string, claim string) (string, error) {
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(jwtRaw, jwt.MapClaims{})
	if err != nil {
		return "", errors.New("Failed to parse JWT token.")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Invalid JWT token payload.")
	}

	return claims[claim].(string), nil
}
