package server

import (
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/dvshur/distributed-signature/pkg/crypto"
	"github.com/dvshur/distributed-signature/pkg/peer"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"
)

type httpErr struct {
	Error string `json:"error"`
}

type httpPk struct {
	PublicKey string `json:"public_key"`
}

type httpSig struct {
	Signature string `json:"signature"`
}

type httpSign struct {
	Data string `json:"data"`
}

const failedParseClientID = "Failed to parse client ID from JWT."
const noSuchClient = "You have not passed a keygen stage yet."

// Create ..
func Create(coord peer.Coordinator) *gin.Engine {
	// logger := log.Logger.Named("router.requestHandler")

	r := gin.Default()
	// gin.DisableConsoleColor()
	// r.Use(gin.Recovery(), accessLog(logger))

	r.Use(cors.Default())

	conf := &aws.Config{Region: aws.String("us-east-2")}
	sess, err := session.NewSession(conf)
	if err != nil {
		panic(err)
	}
	c := cognitoidentityprovider.New(sess)

	identity := NewIdentityManager(c)

	r.PUT("/keygen", func(c *gin.Context) {
		clientID, status, err := identity.ClientID(c.Request)
		if err != nil {
			c.JSON(status, httpErr{Error: err.Error()})
			return
		}

		pk, err := coord.Keygen(clientID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, httpErr{Error: "Failed to generate keys."})
			return
		}

		c.JSON(http.StatusOK, httpPk{PublicKey: pk.String()})
	}).GET("/pubkey", func(c *gin.Context) {
		clientID, status, err := identity.ClientID(c.Request)
		if err != nil {
			c.JSON(status, httpErr{Error: err.Error()})
			return
		}

		pk, ok := coord.GetPublicKey(clientID)
		if !ok {
			c.JSON(http.StatusNoContent, httpErr{Error: noSuchClient})
			return
		}

		c.JSON(http.StatusOK, httpPk{PublicKey: pk.String()})
	}).POST("/sign", func(c *gin.Context) {
		clientID, status, err := identity.ClientID(c.Request)
		if err != nil {
			c.JSON(status, httpErr{Error: err.Error()})
			return
		}

		var req httpSign
		err = c.BindJSON(&req)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusBadRequest, httpErr{Error: "Failed to parse request body."})
			return
		}

		if req.Data == "" {
			c.JSON(http.StatusBadRequest, httpErr{Error: "Empty data."})
			return
		}

		message, err := base58.Decode(req.Data)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusBadRequest, httpErr{Error: "Failed to base58-parse provided data."})
			return
		}

		// todo remove when crypto is stable
		pk, ok := coord.GetPublicKey(clientID)
		if !ok {
			c.JSON(http.StatusBadRequest, httpErr{Error: noSuchClient})
			return
		}

		var sig crypto.Signature
		for {
			sig, err = coord.Sign(clientID, message)
			if err != nil || crypto.Verify(pk, sig, message) {
				break
			}
		}
		// ...and uncomment this
		// sig, err = coord.Sign(clientID, message)

		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, httpErr{Error: "Failed to sign message."})
			return
		}

		c.JSON(http.StatusOK, httpSig{Signature: sig.String()})
	})

	return r
}
