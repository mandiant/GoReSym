/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package main

import (
	"fmt"
	"os"
)

type TaggedStruct struct {
	ID       uint64 `json:"id" db:"user_id"`
	Name     string `json:"name"`
	password string `json:"password"`
	Active   bool
}

func add(a, b int) int      { return a + b }
func multiply(a, b int) int { return a * b }

//go:noinline
func neverInlined(x int) int { return x * x }

func sum(s []int, c chan int) {
	sum := 0
	for _, v := range s {
		sum += v
	}
	c <- sum
}

func main() {
	var Ts TaggedStruct
	Ts.ID = 1234
	Ts.Name = "test"
	Ts.password = "password"
	Ts.Active = true

	fmt.Println(Ts)

	c := make(chan int)
	s := []int{7, 2, 8, 9}
	go sum(s, c)

	messages := make(chan string)
	go func() { messages <- "ping" }()

	fmt.Println("Hello, this is a test")

	msg := <-messages
	fmt.Println(msg)

	x := <-c
	fmt.Println(x)

	n := len(os.Args)
	fmt.Println(add(n, 2))
	fmt.Println(multiply(n, 4))
	fmt.Println(neverInlined(5))
}
