package main

import (
	"crypto-demo/internal/crypto"
	"net/http"
	// "fmt"

	"github.com/gin-gonic/gin"
)

type VerifyReq struct {
	Message string `json:"message" binding:"required"`
	Signature string `json:"signature" binding:"required"`
	PubKey string `json:"pub_key" binding:"required"`
}

func main() {
	r := gin.Default()

	r.POST("/verify", func(c *gin.Context) {
		var req VerifyReq

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		address, err := crypto.VerifyAndGetAddress(req.Message, req.Signature, req.PubKey)
		if err != nil {
			c.JSON (http.StatusUnauthorized, gin.H{"error": "verification failed: " +err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"address": address,
		})
	})

	r.Run(":8080")
}