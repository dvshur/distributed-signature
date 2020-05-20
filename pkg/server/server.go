package server

import (
	"fmt"
	"net/http"

	"github.com/dvshur/distributed-signature/pkg/peer"
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

const failedParseClientId = "Failed to parse client ID from JWT"

// Create ..
func Create(coord peer.Coordinator) *gin.Engine {
	// logger := log.Logger.Named("router.requestHandler")

	r := gin.Default()
	// gin.DisableConsoleColor()
	// r.Use(gin.Recovery(), accessLog(logger))

	r.PUT("/keygen", func(c *gin.Context) {
		clientID, err := getClientID(c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, httpErr{Error: failedParseClientId})
			return
		}

		pk, err := coord.Keygen(clientID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, httpErr{Error: "Failed to generate keys."})
			return
		}

		c.JSON(http.StatusOK, httpPk{PublicKey: pk.String()})
	}).GET("/pubkey", func(c *gin.Context) {
		clientID, err := getClientID(c.Request)
		if err != nil {
			c.JSON(http.StatusBadRequest, httpErr{Error: failedParseClientId})
			return
		}

		pk, ok := coord.GetPublicKey(clientID)
		if !ok {
			c.JSON(http.StatusNotFound, httpErr{Error: "You do not have a public key yet."})
			return
		}

		c.JSON(http.StatusOK, httpPk{PublicKey: pk.String()})
	}).POST("/sign", func(c *gin.Context) {
		var req httpSign
		err := c.BindJSON(&req)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusBadRequest, httpErr{Error: "Failed to parse request body."})
			return
		}

		if req.Data == "" {
			c.JSON(http.StatusBadRequest, httpErr{Error: "Empty data."})
			return
		}

		clientID, err := getClientID(c.Request)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusBadRequest, httpErr{Error: failedParseClientId})
			return
		}

		message, err := base58.Decode(req.Data)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusBadRequest, httpErr{Error: "Failed to base58-parse provided data."})
			return
		}

		sig, err := coord.Sign(clientID, message)

		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, httpErr{Error: "Failed to sign message."})
			return
		}

		c.JSON(http.StatusOK, httpSig{Signature: sig.String()})
	})

	return r
}
