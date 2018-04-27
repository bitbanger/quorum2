package project

// This is the most important file in the project.

import (
	"crypto/sha256"
)

type Hash [sha256.Size]byte
