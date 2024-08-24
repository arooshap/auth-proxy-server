package main

// server provides http+gRPC and pure gRPC server implementations
//
// Copyright (c) 2021 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/dmwm/auth-proxy-server/cric"
	"github.com/dmwm/auth-proxy-server/grpc/cms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Configuration stores server configuration parameters
type Configuration struct {
	Port               int      `json:"port"`         // server port number
	Base               string   `json:"base"`         // base URL
	Verbose            int      `json:"verbose"`      // verbose output
	ServerCrt          string   `json:"server_cert"`  // path to server crt file
	ServerKey          string   `json:"server_key"`   // path to server key file
	RootCA             string   `json:"root_ca"`      // server root CA
	Domain             string   `json:"domain"`       // server domain
	LogFile            string   `json:"log_file"`     // log file
	HttpServer         bool     `json:"http_server"`  // run http service or not
	GRPCAddress        string   `json:"grpc_address"` // address of gRPC backend server
	Providers          []string `json:"providers`     // list of JWKS providers
	CricURL            string   `json:"cric_url"`     // CRIC URL
	CricFile           string   `json:"cric_file"`    // name of the CRIC file
	CricVerbose        int      `json:"cric_verbose"` // verbose output for cric
	UpdateCricInterval int64    `json:"update_cric"`  // interval (in sec) to update cric records
}

// Config variable represents configuration object
var Config Configuration

// helper function to parse configuration
func parseConfig(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Println("Unable to read", err)
		return err
	}
	err = json.Unmarshal(data, &Config)
	if err != nil {
		log.Println("Unable to parse", err)
		return err
	}
	return nil
}

func checkFile(fname string) string {
	_, err := os.Stat(fname)
	if err == nil {
		return fname
	}
	log.Fatalf("unable to read %s, error %v\n", fname, err)
	return ""
}

// our backend gRpc service
var backendGRPC GRPCService

// http server implementation
func grpcHttpServer() {
	// check if provided crt/key files exists
	serverCrt := checkFile(Config.ServerCrt)
	serverKey := checkFile(Config.ServerKey)

	// update CRIC records based on user ID
	go cric.UpdateCricRecords("id", Config.CricFile, Config.CricURL, Config.UpdateCricInterval, Config.CricVerbose)

	// the request handler
	http.HandleFunc(fmt.Sprintf("%s/", Config.Base), RequestHandler)

	// start HTTP or HTTPs server based on provided configuration
	addr := fmt.Sprintf(":%d", Config.Port)
	if serverCrt != "" && serverKey != "" {
		//start HTTPS server which require user certificates
		server := &http.Server{Addr: addr}
		log.Printf("Starting HTTPs server on %s", addr)
		log.Fatal(server.ListenAndServeTLS(serverCrt, serverKey))
	} else {
		log.Fatal("No server certificate files is provided")
	}
}

// gRPC proxy server type
type proxyServer struct {
}

// gRPC proxy server GetData API implementation
func (*proxyServer) GetData(ctx context.Context, request *cms.Request) (*cms.Response, error) {
	if Config.Verbose > 0 {
		log.Println("gRPC request", request)
	}

	// initialize gRPC call to remote backend
	var err error
	if Config.RootCA == "" {
		// non-secure connection
		backendGRPC, err = NewGRPCServiceSimple(Config.GRPCAddress)
	} else {
		// fully secure connection with Token based authentication
		token := request.Data.Token
		backendGRPC, err = NewGRPCService(
			ctx,
			Config.GRPCAddress,
			Config.RootCA,
			Config.Domain,
			token,
			Config.Verbose,
		)
	}
	if err != nil {
		log.Fatal(err)
	}

	response, err := backendGRPC.GetData(request)
	if err != nil {
		log.Println("backend error", err)
		return nil, err
	}
	return response, nil
}

// grpc proxy server implementation
func grpcServer() {

	address := fmt.Sprintf("0.0.0.0:%d", Config.Port)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gRPC server is listening on %v ...\n", address)

	// update CRIC records based on user ID
	go cric.UpdateCricRecords("id", Config.CricFile, Config.CricURL, Config.UpdateCricInterval, Config.CricVerbose)

	// gRPC server options
	var opts []grpc.ServerOption

	// always require authentication token
	opts = append(opts, grpc.UnaryInterceptor(ensureValidToken))

	if Config.ServerCrt != "" && Config.ServerKey != "" {
		// check if provided crt/key files exists
		serverCrt := checkFile(Config.ServerCrt)
		serverKey := checkFile(Config.ServerKey)
		creds, err := credentials.NewServerTLSFromFile(serverCrt, serverKey)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		log.Println("start secure gRPC proxy server with backend gRPC", Config.GRPCAddress)
		opts = append(opts, grpc.Creds(creds))
	} else {
		log.Println("start non-secure gRPC proxy server with backend gRPC", Config.GRPCAddress)
	}
	srv := grpc.NewServer(opts...)
	cms.RegisterDataServiceServer(srv, &proxyServer{})
	srv.Serve(lis)

}

// helper function to validate the authorization.
func valid(authorization []string) bool {
	if Config.Verbose > 0 {
		log.Printf("validate authorization: %+v", authorization)
	}
	if len(authorization) < 1 {
		return false
	}
	token := strings.TrimPrefix(authorization[0], "Bearer ")
	status := validate(token, Config.Providers, Config.Verbose)
	if Config.Verbose > 0 {
		log.Println("validation status", status)
	}
	return status
}

// ensureValidToken ensures a valid token exists within a request's metadata. If
// the token is missing or invalid, the interceptor blocks execution of the
// handler and returns an error. Otherwise, the interceptor invokes the unary
// handler.
func ensureValidToken(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "missing metadata")
	}
	if Config.Verbose > 0 {
		log.Printf("HTTP context metadata: %+v", md)
	}
	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	if !valid(md["authorization"]) {
		log.Println("invalid token, context metadata", md)
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}
	log.Println("token is validated, context metadata", md)

	// Continue execution of handler after ensuring a valid token.
	return handler(ctx, req)
}
