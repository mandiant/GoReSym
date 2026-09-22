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

// nestedInlineSink forces a real memory write inside nestedInner, so its
// contribution can't be algebraically fused into nestedOuter's own arithmetic
// and optimized away entirely (this happened on the first attempt at this
// fixture -- nestedInner's code vanished with no trace to recover).
var nestedInlineSink int

// nestedInner is small enough to inline, but the store to nestedInlineSink is
// a real, non-foldable side effect.
func nestedInner(x int) int {
	nestedInlineSink = x
	return x + 1
}

// nestedOuter calls nestedInner. If both are small enough, the compiler can
// inline nestedInner into nestedOuter, AND THEN inline that already-inlined
// copy of nestedOuter into main.main -- this is the "mid-stack inlining" case:
// nestedInner ends up nested two levels deep inside main.main, with its
// logical caller being nestedOuter (itself inlined), not main.main directly.
func nestedOuter(x int) int {
	y := nestedInner(x)
	return y * 2
}

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
	fmt.Println(nestedOuter(n))
}
