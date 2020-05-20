package server

import (
	"errors"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

func getJwtTokenFromRequest(req *http.Request) (string, error) {
	const bearerToken = "Bearer "

	authorizationHeaderValues := req.Header.Values("Authorization")

	if len(authorizationHeaderValues[0]) < len(bearerToken) || authorizationHeaderValues[0][:len(bearerToken)] != bearerToken {
		return "", errors.New("no access token provided")
	}

	return authorizationHeaderValues[0][len(bearerToken):], nil
}

func getJwtClaim(jwtRaw string, claim string) (string, error) {
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(jwtRaw, jwt.MapClaims{})
	if err != nil {
		return "", errors.New("failed to parse JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid JWT token payload")
	}

	return claims[claim].(string), nil
}

func getClientID(req *http.Request) (string, error) {
	jwt, err := getJwtTokenFromRequest(req)
	if err != nil {
		return "", err
	}

	clientID, err := getJwtClaim(jwt, "sub")
	if err != nil {
		return "", err
	}
	if clientID == "" {
		return "", errors.New("sub is empty")
	}

	return clientID, nil
}
