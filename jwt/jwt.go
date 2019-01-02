package jwt

import (
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	impjwt "gopkg.in/dgrijalva/jwt-go.v3"
)

func getKey() []byte {
	strKey := os.Getenv("JWT_SIGN_KEY")
	if strKey == "" {
		log.Warning("No JWT_SIGN_KEY provided, using default, don't do this in production")
		strKey = "burrah-goric-dixit-tigre-varna-garnet-john"
	}
	return []byte(strKey)
}

// NewToken validates the provided JWT
func NewToken(subject string, expireAfter time.Duration) (string, error) {
	// Create the Claims
	claims := &impjwt.StandardClaims{
		ExpiresAt: time.Now().Add(expireAfter).Unix(),
		Issuer:    "beyondauth",
		Subject:   subject,
	}

	token := impjwt.NewWithClaims(impjwt.SigningMethodHS256, claims)
	// Set some claims
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(getKey())
	return tokenString, err
}

// ValidateToken validates the provided JWT
func ValidateToken(myToken string) (string, error) {
	a, b := impjwt.ParseWithClaims(myToken, &impjwt.StandardClaims{}, func(token *impjwt.Token) (interface{}, error) {
		return getKey(), nil
	})
	if b != nil {
		return "", b
	}
	claims, ok := a.Claims.(*impjwt.StandardClaims)
	if a.Valid && ok {
		return claims.Subject, nil
	}
	return "", errors.New("not sure")
}
