package output

import "fmt"

const (
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	reset  = "\033[0m"
)

// Info prints a cyan [*] status message with newline.
func Info(format string, a ...interface{}) {
	fmt.Printf(cyan+"[*]"+reset+" "+format+"\n", a...)
}

// Success prints a green [+] success message with newline.
func Success(format string, a ...interface{}) {
	fmt.Printf(green+"[+]"+reset+" "+format+"\n", a...)
}

// Warn prints a yellow [!] warning message with newline.
func Warn(format string, a ...interface{}) {
	fmt.Printf(yellow+"[!]"+reset+" "+format+"\n", a...)
}

// Error prints a red [-] error message with newline.
func Error(format string, a ...interface{}) {
	fmt.Printf(red+"[-]"+reset+" "+format+"\n", a...)
}
