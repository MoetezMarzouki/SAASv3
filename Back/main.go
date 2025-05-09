// main.go
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "k3s-backend/proto"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Version information

// Global DB variable for auth functions

// K8s server implementation
type server struct {
	pb.UnimplementedDeploymentServiceServer
	clientset *kubernetes.Clientset
}

// ListDeployments implements the ListDeployments RPC
func (s *server) ListDeployments(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	namespace := req.Namespace
	if namespace == "" {
		namespace = "default"
	}

	// List deployments in the specified namespace
	deployments, err := s.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing deployments: %v", err)
	}

	// Convert to response format
	var deploymentResponses []*pb.Deployment
	for _, deployment := range deployments.Items {
		deploymentResponses = append(deploymentResponses, &pb.Deployment{
			Name:      deployment.Name,
			Namespace: deployment.Namespace,
			Image:     getContainerImage(&deployment),
			Replicas:  *deployment.Spec.Replicas,
			Status:    getDeploymentStatus(&deployment),
			Age:       formatAge(deployment.CreationTimestamp),
		})
	}

	return &pb.ListResponse{
		Deployments: deploymentResponses,
	}, nil
}

// CreateDeployment implements the CreateDeployment RPC
func (s *server) CreateDeployment(ctx context.Context, req *pb.CreateRequest) (*pb.StatusResponse, error) {
	replicas := req.Replicas
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: req.Name,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": req.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": req.Name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  req.Name,
							Image: req.Image,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: req.Port,
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := s.clientset.AppsV1().Deployments(req.Namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return &pb.StatusResponse{
			Success: false,
			Message: fmt.Sprintf("Error creating deployment: %v", err),
		}, nil
	}

	return &pb.StatusResponse{
		Success: true,
		Message: fmt.Sprintf("Deployment %s created successfully in namespace %s", req.Name, req.Namespace),
	}, nil
}

// DeleteDeployment implements the DeleteDeployment RPC
func (s *server) DeleteDeployment(ctx context.Context, req *pb.DeleteRequest) (*pb.StatusResponse, error) {
	namespace := req.Namespace
	if namespace == "" {
		namespace = "default"
	}

	// Delete the deployment
	deletePolicy := metav1.DeletePropagationForeground
	err := s.clientset.AppsV1().Deployments(namespace).Delete(ctx, req.Name, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		return &pb.StatusResponse{
			Success: false,
			Message: fmt.Sprintf("Error deleting deployment: %v", err),
		}, nil
	}

	return &pb.StatusResponse{
		Success: true,
		Message: fmt.Sprintf("Deployment %s in namespace %s deleted successfully", req.Name, req.Namespace),
	}, nil
}

// ListNamespaces implements the ListNamespaces RPC
func (s *server) ListNamespaces(ctx context.Context, _ *pb.Empty) (*pb.NamespacesResponse, error) {
	// List all namespaces
	namespaces, err := s.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing namespaces: %v", err)
	}

	// Extract namespace names
	var namespaceNames []string
	for _, ns := range namespaces.Items {
		namespaceNames = append(namespaceNames, ns.Name)
	}

	return &pb.NamespacesResponse{
		Namespaces: namespaceNames,
	}, nil
}

// formatAge formats the duration since creation into a human-readable string
func formatAge(creationTimestamp metav1.Time) string {
	duration := time.Since(creationTimestamp.Time)

	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60

	if hours >= 48 {
		days := hours / 24
		return fmt.Sprintf("%dd", days)
	} else if hours >= 1 {
		return fmt.Sprintf("%dh", hours)
	} else {
		return fmt.Sprintf("%dm", minutes)
	}
}

// getDeploymentStatus determines the overall status of a deployment
func getDeploymentStatus(deployment *appsv1.Deployment) string {
	if deployment.Status.ReadyReplicas == deployment.Status.Replicas &&
		deployment.Status.Replicas == *deployment.Spec.Replicas {
		return "Running"
	} else if deployment.Status.ReadyReplicas == 0 {
		return "Pending"
	} else {
		return "Updating"
	}
}

// getContainerImage gets the first container's image from a deployment
func getContainerImage(deployment *appsv1.Deployment) string {
	if len(deployment.Spec.Template.Spec.Containers) > 0 {
		return deployment.Spec.Template.Spec.Containers[0].Image
	}
	return ""
}

// startGRPCServer starts the gRPC server in a separate goroutine
func startGRPCServer(clientset *kubernetes.Clientset) {
	// Create gRPC server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterDeploymentServiceServer(s, &server{clientset: clientset})

	// Enable reflection for tools like grpcurl
	reflection.Register(s)

	log.Printf("gRPC server listening on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// startHTTPSServer starts the HTTPS server in a separate goroutine
func startHTTPSServer(router *mux.Router, tlsConfig *tls.Config, port int) {
	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:      addr,
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting HTTPS server on %s", addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

func main() {
	// Command line flags
	var (
		httpsPort  = flag.Int("https-port", 8443, "Port to listen on for HTTPS")
		dbHost     = flag.String("db-host", "localhost", "PostgreSQL host")
		dbPort     = flag.Int("db-port", 5432, "PostgreSQL port")
		dbUser     = flag.String("db-user", "postgres", "PostgreSQL user")
		dbPassword = flag.String("db-password", "", "PostgreSQL password")
		dbName     = flag.String("db-name", "auth", "PostgreSQL database name")
		certFile   = flag.String("cert", "server.crt", "Path to SSL certificate")
		keyFile    = flag.String("key", "server.key", "Path to SSL key")
		caFile     = flag.String("ca", "", "Path to CA certificate (for client auth)")
		clientAuth = flag.Bool("client-auth", false, "Enable client certificate verification")
		genCerts   = flag.Bool("gen-certs", false, "Print commands to generate certificates and exit")
		kubeconfig = flag.String("kubeconfig", "./KUBECONFIG.yaml", "Path to kubeconfig file")
	)
	flag.Parse()

	// Check for environment variables
	if envHost := os.Getenv("DB_HOST"); envHost != "" {
		*dbHost = envHost
	}
	if envPort := os.Getenv("DB_PORT"); envPort != "" {
		fmt.Sscanf(envPort, "%d", dbPort)
	}
	if envUser := os.Getenv("DB_USER"); envUser != "" {
		*dbUser = envUser
	}
	if envPassword := os.Getenv("DB_PASSWORD"); envPassword != "" {
		*dbPassword = envPassword
	}
	if envName := os.Getenv("DB_NAME"); envName != "" {
		*dbName = envName
	}
	if envHTTPSPort := os.Getenv("HTTPS_PORT"); envHTTPSPort != "" {
		fmt.Sscanf(envHTTPSPort, "%d", httpsPort)
	}
	if envKubeconfig := os.Getenv("KUBECONFIG"); envKubeconfig != "" {
		*kubeconfig = envKubeconfig
	}

	// Print certificate generation commands if requested
	if *genCerts {
		fmt.Println(GenerateClientCert())
		os.Exit(0)
	}

	// Initialize Kubernetes client
	log.Printf("Using kubeconfig from: %s", *kubeconfig)
	if _, err := os.Stat(*kubeconfig); os.IsNotExist(err) {
		log.Fatalf("Kubeconfig file not found at %s", *kubeconfig)
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}
	log.Println("Successfully connected to Kubernetes cluster")

	// Check certificate files
	if _, err := os.Stat(*certFile); os.IsNotExist(err) {
		log.Printf("Certificate file %s does not exist", *certFile)
		log.Println("You can use the -gen-certs flag to print commands for generating certificates")
		os.Exit(1)
	}

	if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
		log.Printf("Key file %s does not exist", *keyFile)
		log.Println("You can use the -gen-certs flag to print commands for generating certificates")
		os.Exit(1)
	}

	// Connect to PostgreSQL
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		*dbHost, *dbPort, *dbUser, *dbPassword, *dbName)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}

	// Verify database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	defer db.Close()
	log.Printf("Connected to PostgreSQL database: %s", *dbName)

	// Initialize auth system
	DB = db
	createTables()

	// Set up router for HTTP server
	router := mux.NewRouter()

	// Health check route
	router.HandleFunc("/health", HealthHandler).Methods("GET")

	// Public routes
	router.HandleFunc("/api/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/api/login", LoginHandler).Methods("POST")

	// Private routes (require authentication)
	private := router.PathPrefix("/api").Subrouter()
	private.Use(AuthMiddleware)
	private.HandleFunc("/logout", LogoutHandler).Methods("POST")
	private.HandleFunc("/profile", ProfileHandler).Methods("GET")

	// TLS configuration
	clientAuthType := tls.NoClientCert
	if *clientAuth {
		clientAuthType = tls.RequireAndVerifyClientCert
	}

	tlsConfig := ConfigureTLS(TLSConfig{
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		CAFile:     *caFile,
		ClientAuth: clientAuthType,
	})

	// Start servers in separate goroutines
	go startHTTPSServer(router, tlsConfig, *httpsPort)
	go startGRPCServer(clientset)

	// Keep the main goroutine alive
	select {}
}

// ProfileHandler returns the current user's profile
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusUnauthorized, "Authorization header required")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		respondWithError(w, http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
		return
	}

	token := parts[1]

	user, err := GetCurrentUser(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, user)
}
