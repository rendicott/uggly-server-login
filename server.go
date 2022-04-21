package main

import (
	"context"
	"flag"
	"reflect"
	"fmt"
	pb "github.com/rendicott/uggly"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"log"
	"net"
	"time"
)

var (
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert_file", "", "The TLS cert file")
	keyFile    = flag.String("key_file", "", "The TLS key file")
	port       = flag.Int("port", 10000, "The server port")
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")
var strokeMap = []string{"1","2","3","4","5","6","7","8","9",
	"a","b","c","d","e","f","g","h","i","j","k","l","m",
	"n","o","p","q","r","s","t","u","v","w","x","y","z"}

func shelp(fg, bg string) *pb.Style {
	return &pb.Style{
		Fg:   fg,
		Bg:   bg,
		Attr: "4",
	}
}

var users map[string]string
var sessions map[string]string

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
    return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func pageGeneratorSimple(w, h int, text string) (*pb.PageResponse) {
	localPage := pb.PageResponse{
		Name: "generated",
		DivBoxes: &pb.DivBoxes{},
		Elements: &pb.Elements{},
	}
	localPage.DivBoxes.Boxes = append(localPage.DivBoxes.Boxes, &pb.DivBox{
		Name:     "generated",
		Border:   true,
		BorderW:  int32(1),
		BorderChar: convertStringCharRune("^"),
		FillChar: convertStringCharRune(""),
		StartX:   5,
		StartY:   5,
		Width:    int32(w-10),
		Height:   int32(h-15),
		BorderSt: shelp("orange", "black"),
		FillSt: shelp("white","black"),
	})
	localPage.Elements.TextBlobs = append(localPage.Elements.TextBlobs, &pb.TextBlob{
		Content: text,
		Wrap:    true,
		Style: &pb.Style{
			Fg:   "white",
			Bg:   "black",
			Attr: "4",
		},
		DivNames: []string{"generated"},
	})
	return &localPage
}

func addLink(presp *pb.PageResponse, keyStroke, pageName string) (*pb.PageResponse) {
	presp.KeyStrokes = append(presp.KeyStrokes, &pb.KeyStroke{
		KeyStroke: keyStroke,
		Action: &pb.KeyStroke_Link{
			Link: &pb.Link{
				PageName: pageName,
	}}})
	return presp
}

func logout(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	var session string
	for _, cookie := range preq.SendCookies{
		if cookie.Key == "sessionid" {
			session = cookie.Value
		}
	}
	log.Printf("deleting session %s", session)
	username := "unknown"
	var ok bool
	if username, ok = sessions[session]; ok {
		delete(sessions, session)
	}
	height := int(preq.ClientHeight)
	width := int(preq.ClientWidth)
	msg := fmt.Sprintf("%s, you are now logged out. Log back in with (l)", username)
	localPage := pageGeneratorSimple(width, height, msg)
	localPage = addLink(localPage, "l", "login")
	// cleaning up client side
	log.Println("blanking sessionid cookie")
	localPage.SetCookies = append(localPage.SetCookies, &pb.Cookie{
		Key: "sessionid",
		Value: "",
	})
	return localPage, err
}



func newUserSubmit(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	sizeOfVar := reflect.TypeOf(&preq).Size()
	log.Printf("newUserSubmit: processing %d bytes of PageRequest", sizeOfVar)
	height := int(preq.ClientHeight)
	width := int(preq.ClientWidth)
	var username string
	var password1 string
	var password2 string
	for _, fd := range preq.FormData {
		for _, td := range fd.TextBoxData {
			if td.Name == "username" {
				username = td.Contents
			}
			if td.Name == "password1" {
				password1 = td.Contents
			}
			if td.Name == "password2" {
				password2 = td.Contents
			}
		}
	}
	if _, ok := users[username]; ok {
		msg := fmt.Sprintf("username '%s' already exists. Try again (n).", username)
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "n", "newUser")
		return localPage, err
	} else if password1 == password2 {
		hashPass, err := hashPassword(password1)
		users[username] = hashPass
		msg := fmt.Sprintf("Hi %s. Thanks for creating a user. Now user your new login (l)", username) 
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "l", "login")
		return localPage, err
	} else if password1 != password2 {
		msg := "passwords did not match. Try again (n)"
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "n", "newUser")
		return localPage, err
	}
	return login(ctx, preq)
}

func loginSubmit(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	sizeOfVar := reflect.TypeOf(&preq).Size()
	log.Printf("loginSubmit: processing %d bytes of PageRequest", sizeOfVar)
	height := int(preq.ClientHeight)
	width := int(preq.ClientWidth)
	var username string
	var password string
	for _, fd := range preq.FormData {
		for _, td := range fd.TextBoxData {
			if td.Name == "username" {
				username = td.Contents
			}
			if td.Name == "password" {
				password = td.Contents
			}
		}
	}
	sessionID, ok := passwordValid(username, password)
	if ok {
		log.Println("username and password successful")
		msg := fmt.Sprintf("Hi %s. You may now navigate to protected pages " +
			"like /protected by hitting (p) or selecting 'protected' from the feedBrowser", username)
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "p", "protected")
		localPage.SetCookies = append(localPage.SetCookies, &pb.Cookie{
			Key: "username",
			Value: username,
			Metadata: true, // make sure it gets sent with metadata so validator doesn't throw it out
			Secure: true,
			Expires: (time.Now().Add(time.Duration(5*time.Hour))).Format(time.RFC1123),
		})
		log.Println("setting sessionid cookie")
		localPage.SetCookies = append(localPage.SetCookies, &pb.Cookie{
			Key: "sessionid",
			Value: sessionID,
			Metadata: true, // make sure it gets sent with metadata so validator doesn't throw it out
			Secure: true,
			Expires: (time.Now().Add(time.Duration(5*time.Hour))).Format(time.RFC1123),
		})
		return localPage, err
	} else if sessionID == "user not found" && !ok {
		msg := "Passord incorrect. Try again (l) or create a new user (n)"
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "n", "newUser")
		localPage = addLink(localPage, "l", "login")
		return localPage, err
	} else {
		msg := fmt.Sprintf("username '%s' not found. Create new user (n) or try again (l)", username)
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "n", "newUser")
		localPage = addLink(localPage, "l", "login")
		return localPage, err
	}
	return login(ctx, preq)
}



func protected(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	sizeOfVar := reflect.TypeOf(&preq).Size()
	log.Printf("protected: processing %d bytes of PageRequest", sizeOfVar)
	var session string
	var user string
	for _, cookie := range preq.SendCookies{
		if cookie.Key == "sessionid" {
			session = cookie.Value
		}
		if cookie.Key == "username" {
			user = cookie.Value
		}
	}
	// even though the validateCtx function should protect this page we'll verify again
	// just to be safe
	if sessionValid(session) {
		log.Print("session valid, letting them in")
		height := int(preq.ClientHeight)
		width := int(preq.ClientWidth)
		msg := fmt.Sprintf("Hi '%s'. This is the super secret page. Press (o) to logout.", user)
		localPage := pageGeneratorSimple(width, height, msg)
		localPage = addLink(localPage, "o", "logout")
		return localPage, err
	}
	log.Printf("unable to validate session '%s', returning user to login", session)
	return login(ctx, preq)
}

func sessionValid(session string) (bool) {
	if _, ok := sessions[session]; ok {
		return true
	}
	return false
}

func passwordValid(username, password string) (string, bool) {
	if userHashPass, ok := users[username]; ok {
		if checkPasswordHash(password, userHashPass) {
			session := randStringRunes(16)
			sessions[session] = username
			return session, true
		}
	}
	return "user not found", false
}


func validateCtx(ctx context.Context) (bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	sizeOfVar := reflect.TypeOf(&md).Size()
	log.Printf("processed %d bytes to make validation decision", sizeOfVar)
	if ok {
		log.Printf("form got incoming metadata: %v", md)
		if id, ok := md["sessionid"]; ok {
			log.Printf("got sessionid: %s", id)
			return true
		} else {
			log.Printf("no sessionid found in CTX metadata, redirecting to login")
			return false
		}
	} else {
		log.Print("form no metadata received")
		return false
	}
	return false
}

func newUser(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	height := int(preq.ClientHeight)
	width := int(preq.ClientWidth)
	localPage := pb.PageResponse{
		Name: "form",
		DivBoxes: &pb.DivBoxes{},
		Elements: &pb.Elements{},
	}
	formActivationKeystroke := "j"
	instructionsMessage := fmt.Sprintf("Create a new user. Hit (%s) to activate form.", formActivationKeystroke)
	localPage.DivBoxes.Boxes = append(localPage.DivBoxes.Boxes, &pb.DivBox{
		Name:     "formDiv",
		Border:   true,
		BorderW:  int32(1),
		BorderChar: convertStringCharRune("^"),
		FillChar: convertStringCharRune(""),
		StartX:   5,
		StartY:   5,
		Width:    int32(width-10),
		Height:   int32(height-15),
		BorderSt: shelp("orange", "black"),
		FillSt: shelp("white","black"),
	})
	loginFormName := "newUserForm"
	positionX := 30
	localPage.Elements.Forms = append(localPage.Elements.Forms, &pb.Form{
		Name: loginFormName,
		DivName: "formDiv",
		SubmitLink: &pb.Link{
			PageName: "newUserSubmit",
		},
		TextBoxes: []*pb.TextBox{
			&pb.TextBox{
				Name: "password1",
				TabOrder: 2,
				DefaultValue: "",
				Description: "Password: ",
				PositionX: int32(positionX),
				PositionY: 12,
				Height: 1,
				Width: 30,
				StyleCursor: shelp("black", "gray"),
				StyleFill: shelp("black", "blue"),
				StyleText: shelp("white", "blue"),
				StyleDescription: shelp("red", "black"),
				ShowDescription: true,
				Password: true,
			},
			&pb.TextBox{
				Name: "password2",
				TabOrder: 3,
				DefaultValue: "",
				Description: "Re-Type Password: ",
				PositionX: int32(positionX),
				PositionY: 14,
				Height: 1,
				Width: 30,
				StyleCursor: shelp("black", "gray"),
				StyleFill: shelp("black", "blue"),
				StyleText: shelp("white", "blue"),
				StyleDescription: shelp("red", "black"),
				ShowDescription: true,
				Password: true,
			},
			&pb.TextBox{
				Name: "username",
				TabOrder: 1,
				DefaultValue: "",
				Description: "Username: ",
				PositionX: int32(positionX),
				PositionY: 10,
				Height: 1,
				Width: 30,
				StyleCursor: shelp("black", "gray"),
				StyleFill: shelp("black", "blue"),
				StyleText: shelp("white", "blue"),
				StyleDescription: shelp("red", "black"),
				ShowDescription: true,
			},
		},
	})
	localPage.KeyStrokes = append(localPage.KeyStrokes, &pb.KeyStroke{
		KeyStroke: formActivationKeystroke,
		Action: &pb.KeyStroke_FormActivation{
			FormActivation: &pb.FormActivation{
				FormName: loginFormName,
	}}})
	localPage.Elements.TextBlobs = append(localPage.Elements.TextBlobs, &pb.TextBlob{
		Content: instructionsMessage,
		Wrap:    true,
		Style: &pb.Style{
			Fg:   "white",
			Bg:   "black",
			Attr: "4",
		},
		DivNames: []string{"formDiv"},
	})
	return &localPage, err
}



func login(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	height := int(preq.ClientHeight)
	width := int(preq.ClientWidth)
	localPage := pb.PageResponse{
		Name: "form",
		DivBoxes: &pb.DivBoxes{},
		Elements: &pb.Elements{},
	}
	formActivationKeystroke := "j"
	welcomeMessage := fmt.Sprintf("Please login. Hit (%s) to activate form.", formActivationKeystroke)
	localPage.DivBoxes.Boxes = append(localPage.DivBoxes.Boxes, &pb.DivBox{
		Name:     "formDiv",
		Border:   true,
		BorderW:  int32(1),
		BorderChar: convertStringCharRune("^"),
		FillChar: convertStringCharRune(""),
		StartX:   5,
		StartY:   5,
		Width:    int32(width-10),
		Height:   int32(height-15),
		BorderSt: shelp("orange", "black"),
		FillSt: shelp("white","black"),
	})
	loginFormName := "loginForm"
	localPage.Elements.Forms = append(localPage.Elements.Forms, &pb.Form{
		Name: loginFormName,
		DivName: "formDiv",
		SubmitLink: &pb.Link{
			PageName: "loginSubmit",
		},
		TextBoxes: []*pb.TextBox{
			&pb.TextBox{
				Name: "password",
				TabOrder: 2,
				DefaultValue: "",
				Description: "Password: ",
				PositionX: 25,
				PositionY: 12,
				Height: 1,
				Width: 30,
				StyleCursor: shelp("black", "gray"),
				StyleFill: shelp("black", "blue"),
				StyleText: shelp("white", "blue"),
				StyleDescription: shelp("red", "black"),
				ShowDescription: true,
				Password: true,
			},
			&pb.TextBox{
				Name: "username",
				TabOrder: 1,
				DefaultValue: "",
				Description: "Username: ",
				PositionX: 25,
				PositionY: 10,
				Height: 1,
				Width: 30,
				StyleCursor: shelp("black", "gray"),
				StyleFill: shelp("black", "blue"),
				StyleText: shelp("white", "blue"),
				StyleDescription: shelp("red", "black"),
				ShowDescription: true,
			},
		},
	})
	localPage.KeyStrokes = append(localPage.KeyStrokes, &pb.KeyStroke{
		KeyStroke: formActivationKeystroke,
		Action: &pb.KeyStroke_FormActivation{
			FormActivation: &pb.FormActivation{
				FormName: loginFormName,
	}}})
	localPage.Elements.TextBlobs = append(localPage.Elements.TextBlobs, &pb.TextBlob{
		Content: welcomeMessage,
		Wrap:    true,
		Style: &pb.Style{
			Fg:   "white",
			Bg:   "black",
			Attr: "4",
		},
		DivNames: []string{"formDiv"},
	})
	return &localPage, err
}

/* GetPage implements the Page Service's GetPage method as required in the protobuf definition.

It is the primary listening method for the server. It accepts a PageRequest and then attempts to build
a PageResponse which the client will process and display on the client's pcreen. 
*/
func (s pageServer) GetPage(ctx context.Context, preq *pb.PageRequest) (presp *pb.PageResponse, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		log.Printf("got incoming metadata: %v", md)
	} else {
		log.Print("no metadata received")
	}
	if preq.Name == "login" {
		if validateCtx(ctx) {
			return protected(ctx, preq)
		} else {
			return login(ctx, preq)
		}
	} else if preq.Name == "loginSubmit" {
		return loginSubmit(ctx, preq)
	} else if preq.Name == "logout" {
		return logout(ctx, preq)
	} else if preq.Name == "newUser" {
		return newUser(ctx, preq)
	} else if preq.Name == "newUserSubmit" {
		return newUserSubmit(ctx, preq)
	} else if preq.Name == "protected" {
		if validateCtx(ctx) {
			return protected(ctx, preq)
		} else {
			return login(ctx, preq)
		}
	}
	return login(ctx, preq)
}

/* newPageServer takes the loaded pageconfig YAML and converts it to the structs
required so that the GetPage method can adequately respond with a PageResponse.
*/
func newPageServer() *pageServer {
	pServer := &pageServer{}
	return pServer
}


/* pageServer is a struct from which to attach the required methods for the Page Service
as defined in the protobuf definition
*/
type pageServer struct {
	pb.UnimplementedPageServer
	//pages []*pageServerPage
}

// convertStringCharRune takes a string and converts it to a rune slice
// then grabs the rune at index 0 in the slice so that it can return
// an int32 to satisfy the Uggly protobuf struct for border and fill chars
// and such. If the input string is less than zero length then it will just
// rune out a space char and return that int32.
func convertStringCharRune(s string) int32 {
	if len(s) == 0 {
		s = " "
	}
	runes := []rune(s)
	return runes[0]
}

/* feedServer is a struct from which to attach the required methods for the Feed Service
as defined in the protobuf definition
*/
type feedServer struct {
	pb.UnimplementedFeedServer
	pages []*pb.PageListing
}

/* newFeedServer generates a feed of pages this server wants to expose in an
index to a client that requests it
*/
func newFeedServer() *feedServer {
	fServer := &feedServer{}
	// ./server.go:82:17: first argument to append must be slice; have *uggly.Pages
	fServer.pages = append(fServer.pages, &pb.PageListing{
		Name: "login",
	})
	fServer.pages = append(fServer.pages, &pb.PageListing{
		Name: "newUser",
	})
	fServer.pages = append(fServer.pages, &pb.PageListing{
		Name: "logout",
	})
	fServer.pages = append(fServer.pages, &pb.PageListing{
		Name: "protected",
	})
	return fServer
}

/* GetFeed implements the Feed Service's GetFeed method as required in the protobuf definition.

It is the primary listening method for the server. It accepts a FeedRequest and then attempts to build
a FeedResponse which the client will process. 
*/
func (f feedServer) GetFeed(ctx context.Context, freq *pb.FeedRequest) (fresp *pb.FeedResponse, err error) {
	fresp = &pb.FeedResponse{}
	fresp.Pages = f.pages
	return fresp, err
}


func main() {
	flag.Parse()
	//lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("ERROR with TLS cert: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Println("Running secure")
	} else {
		log.Println("No TLS options specified, running insecure")
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	users = make(map[string]string, 0)
	sessions = make(map[string]string, 0)
	hashPass, err := hashPassword("pass")
	users["admin"] = hashPass
	hashPass, err = hashPassword("lass")
	users["user"] = hashPass
	grpcServer := grpc.NewServer(opts...)
	f := newFeedServer()
	pb.RegisterFeedServer(grpcServer, *f)
	s := newPageServer()
	pb.RegisterPageServer(grpcServer, *s)
	log.Println("Server listening")
	grpcServer.Serve(lis)
}
