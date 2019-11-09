package main

import (
	"fmt"
	"github.com/yerden/go-snf/snf"
)

func main() {
	fmt.Println("vim-go")

	if err := snf.Init(); err != nil {
		panic(err.Error())
	}

	ifa, err := snf.GetIfAddrs()
	if err != nil {
		panic(err.Error())
	}

	for _, i := range ifa {
		fmt.Println(&i)
	}
}
