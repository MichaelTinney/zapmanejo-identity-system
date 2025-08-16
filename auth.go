// auth.go - Authentication system for ZapManejo
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// JWT Claims structure
type Claims struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	IsActive    bool   `json:"is_active"`
	jwt.RegisteredClaims
}

// Registration request structure
type RegisterRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

// Login request structure
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Auth response structure
type AuthResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	Token        string `json:"token,omitempty"`
	User         *User  `json:"user,omitempty"`
	VerificationCode string `json:"verification_code,omitempty"`
}

// Email verification structure
type EmailVerification struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	UserID      primitive.ObjectID `bson:"user_id"`
	Email       string             `bson:"email"`
	Code        string             `bson:"code"`
	ExpiresAt   time.Time          `bson:"expires_at"`
	CreatedAt   time.Time          `bson:"created_at"`
	IsUsed      bool               `bson:"is_used"`
}

// JWT secret key from environment
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// Generate random verification code
func generateVerificationCode() string {
	bytes := make([]byte, 3)
	rand.Read(bytes)
	return fmt.Sprintf("%06d", int(hex.EncodeToString(bytes)[0:6]))
}

// Generate JWT token
func generateJWTToken(user *User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	
	claims := &Claims{
		UserID:      user.ID.Hex(),
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		IsActive:    user.IsActive,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "zapmanejo",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Validate JWT token
func validateJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// Store email verification code
func storeVerificationCode(userID primitive.ObjectID, email string) (string, error) {
	code := generateVerificationCode()
	
	verification := EmailVerification{
		UserID:    userID,
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minute expiry
		CreatedAt: time.Now(),
		IsUsed:    false,
	}

	collection := dbConn.Database("mydatabase").Collection("email_verifications")
	_, err := collection.InsertOne(context.TODO(), verification)
	if err != nil {
		return "", err
	}

	return code, nil
}

// Verify email code
func verifyEmailCode(email, code string) (*User, error) {
	collection := dbConn.Database("mydatabase").Collection("email_verifications")
	
	var verification EmailVerification
	filter := bson.M{
		"email":      email,
		"code":       code,
		"is_used":    false,
		"expires_at": bson.M{"$gt": time.Now()},
	}
	
	err := collection.FindOne(context.TODO(), filter).Decode(&verification)
	if err != nil {
		return nil, errors.New("invalid or expired verification code")
	}

	// Mark verification as used
	update := bson.M{"$set": bson.M{"is_used": true}}
	collection.UpdateOne(context.TODO(), bson.M{"_id": verification.ID}, update)

	// Activate user account
	userCollection := dbConn.Database("mydatabase").Collection("users")
	userUpdate := bson.M{"$set": bson.M{"is_active": true}}
	userCollection.UpdateOne(context.TODO(), bson.M{"_id": verification.UserID}, userUpdate)

	// Return updated user
	var user User
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": verification.UserID}).Decode(&user)
	return &user, err
}

// Link WhatsApp phone number to user account
func linkPhoneNumber(userID primitive.ObjectID, phoneNumber string) error {
	collection := dbConn.Database("mydatabase").Collection("users")
	update := bson.M{"$set": bson.M{"phone_number": phoneNumber}}
	_, err := collection.UpdateOne(context.TODO(), bson.M{"_id": userID}, update)
	return err
}

// Register new user handler
func HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{Success: false, Message: "Invalid request format"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" || req.Username == "" {
		response := AuthResponse{Success: false, Message: "Email, username and password are required"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if user already exists
	collection := dbConn.Database("mydatabase").Collection("users")
	var existingUser User
	err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&existingUser)
	if err == nil {
		response := AuthResponse{Success: false, Message: "User with this email already exists"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Hash password using Mark's existing system
	hashedPassword, err := GetSalted(req.Password)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error processing password"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create new user
	user := User{
		Username:    req.Username,
		Email:       req.Email,
		Password:    hashedPassword,
		PhoneNumber: req.PhoneNumber,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    false, // Will be activated after email verification
	}

	result, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error creating user account"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get the inserted user ID
	userID := result.InsertedID.(primitive.ObjectID)
	user.ID = userID

	// Generate and store verification code
	verificationCode, err := storeVerificationCode(userID, req.Email)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error generating verification code"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Send verification email using Mark's existing email system
	err = SendRegistrationEmail(req.Email, verificationCode)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error sending verification email"}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := AuthResponse{
		Success: true,
		Message: "Registration successful. Please check your email for verification code.",
		User:    &user,
		VerificationCode: verificationCode, // For testing purposes
	}
	json.NewEncoder(w).Encode(response)
}

// Login user handler
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{Success: false, Message: "Invalid request format"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Hash password for comparison
	hashedPassword, err := GetSalted(req.Password)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Authentication failed"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Find user with email and password
	collection := dbConn.Database("mydatabase").Collection("users")
	var user User
	filter := bson.M{
		"email":    req.Email,
		"password": hashedPassword,
	}

	err = collection.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Invalid email or password"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if account is active
	if !user.IsActive {
		response := AuthResponse{Success: false, Message: "Account not verified. Please check your email."}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate JWT token
	token, err := generateJWTToken(&user)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error generating authentication token"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Clear password from response
	user.Password = ""

	response := AuthResponse{
		Success: true,
		Message: "Login successful",
		Token:   token,
		User:    &user,
	}
	json.NewEncoder(w).Encode(response)
}

// Email verification handler
func HandleEmailVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{Success: false, Message: "Invalid request format"}
		json.NewEncoder(w).Encode(response)
		return
	}

	user, err := verifyEmailCode(req.Email, req.Code)
	if err != nil {
		response := AuthResponse{Success: false, Message: err.Error()}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate JWT token for verified user
	token, err := generateJWTToken(user)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error generating authentication token"}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Clear password from response
	user.Password = ""

	response := AuthResponse{
		Success: true,
		Message: "Email verified successfully",
		Token:   token,
		User:    user,
	}
	json.NewEncoder(w).Encode(response)
}

// WhatsApp phone linking handler
func HandleLinkPhoneNumber(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user from JWT token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		response := AuthResponse{Success: false, Message: "Authorization header required"}
		json.NewEncoder(w).Encode(response)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	claims, err := validateJWTToken(tokenString)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Invalid authentication token"}
		json.NewEncoder(w).Encode(response)
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{Success: false, Message: "Invalid request format"}
		json.NewEncoder(w).Encode(response)
		return
	}

	userID, _ := primitive.ObjectIDFromHex(claims.UserID)
	err = linkPhoneNumber(userID, req.PhoneNumber)
	if err != nil {
		response := AuthResponse{Success: false, Message: "Error linking phone number"}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := AuthResponse{
		Success: true,
		Message: "Phone number linked successfully",
	}
	json.NewEncoder(w).Encode(response)
}

// Authentication middleware
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims, err := validateJWTToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
			return
		}

		// Add user info to request context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "user_email", claims.Email)
		ctx = context.WithValue(ctx, "phone_number", claims.PhoneNumber)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Auto-register from WhatsApp message
func AutoRegisterFromWhatsApp(phoneNumber, name string) (*User, error) {
	collection := dbConn.Database("mydatabase").Collection("users")
	
	// Check if user already exists with this phone number
	var existingUser User
	err := collection.FindOne(context.TODO(), bson.M{"phone_number": phoneNumber}).Decode(&existingUser)
	if err == nil {
		return &existingUser, nil // User already exists
	}

	// Create auto-generated email and username
	email := fmt.Sprintf("%s@whatsapp.zapmanejo.com", phoneNumber)
	username := fmt.Sprintf("whatsapp_%s", phoneNumber)
	
	// Generate random password for WhatsApp users
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	randomPassword := hex.EncodeToString(randomBytes)
	
	hashedPassword, err := GetSalted(randomPassword)
	if err != nil {
		return nil, err
	}

	// Create new WhatsApp user (auto-activated)
	user := User{
		Username:    username,
		Email:       email,
		Password:    hashedPassword,
		PhoneNumber: phoneNumber,
		Name:        name,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true, // WhatsApp users are auto-activated
	}

	result, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		return nil, err
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	return &user, nil
}

// Updated User struct to include additional fields
type User struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username    string             `json:"username"`
	Email       string             `json:"email"`
	Password    string             `json:"-"` // Excluded from JSON responses
	PhoneNumber string             `json:"phone_number"`
	Name        string             `json:"name"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	IsActive    bool               `json:"is_active"`
}

// Password validation function (integrates with Mark's existing password.go)
func GetSalted(password string) (string, error) {
	// This should call Mark's existing GetSalted function from password.go
	// Placeholder - replace with actual import/call to Mark's password package
	return fmt.Sprintf("hashed_%s", password), nil
}

// Email sending function (integrates with Mark's existing email.go)
func SendRegistrationEmail(to, code string) error {
	// This should call Mark's existing SendRegistrationEmail function
	// Placeholder - replace with actual import/call to Mark's email package
	fmt.Printf("Sending email to %s with code %s\n", to, code)
	return nil
}
