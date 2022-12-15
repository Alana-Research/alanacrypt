package alanacrypt

import (
	"sync"
)

var logMutex sync.Mutex

// Should be used to provide custom logging writers for the SDK to use.
type Logger interface {
	Log(...interface{})
}

//Wrapper for client to satisfy Logger interface
// Ex: alanacrypt.LoggerFunc(func(args ...interface{}) {
//         fmt.Fprintln(os.Stdout, args...)
//     }
type LoggerFunc func(...interface{})

// Log calls the wrapped function with the arguments provided
func (f LoggerFunc) Log(args ...interface{}) {
	f(args...)
}
