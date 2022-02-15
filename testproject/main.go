package main

import "fmt"

type structurea struct {
	test string
}

func sum(s []int, c chan int) {
	sum := 0
	for _, v := range s {
		sum += v
	}
	c <- sum
}

func main() {
	var structa structurea
	structa.test = "hi"

	fmt.Println(structa)

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
}
