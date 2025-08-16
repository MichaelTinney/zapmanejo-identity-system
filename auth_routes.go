// auth_routes.go - Authentication routes for Mark's serverless architecture
package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
)

// Updated main.go to include authentication routes
func MainWithAuth(args map[string]interface{}) Response {
	// Handle hub challenge (existing code)
	challenge, isHubChallenge := args["hub.challenge"]
	mode, isHubMode := args["hub.mode"]
	token, isHubToken := args["hub.verify_token"]
	entry, isEntryRequest := args["entry"]
	isHubRequest := isHubChallenge && isHubMode && isHubToken

	if !isEntryRequest && !isHubRequest {
		// Check if this is an HTTP request for authentication
		httpData, isHTTP := args["http"]
		if isHTTP {
			return handleHTTPRequest(httpData)
		}
		return FunctionError("unknown_request_type")
	}

	// Handle WhatsApp entry request (existing code)
	if isEntryRequest {
		data, err := json.Marshal(entry)
		if err != nil {
			return FunctionError(err)
		}

		// Process entries and auto-register users if needed
		err = HandleEntryRequestWithAuth(string(data))
		if err != nil {
			return FunctionError(err)
		}
	}

	// Handle hub validation (existing code)
	if isHubRequest {
		if err := HandleHubRequest(challenge.(string), mode.(string), token.(string)); err != nil {
			return FunctionError(err)
		}
	}

	return FunctionSuccess("success")
}

// Enhanced entry processing with auto-registration
func HandleEntryRequestWithAuth(entry string) error {
	dbConnect()
	defer dbConn.Disconnect(context.TODO())
	
	entries := []Entry{}
	err := json.Unmarshal([]byte(entry), &entries)
	if err != nil {
		return err
	}

	return ProcessEntriesWithAuth(entries)
}

// Enhanced entry processing that handles user registration
func ProcessEntriesWithAuth(entries []Entry) error {
	for _, entry := range entries {
		err := entry.ProcessWithAuth()
		if err != nil {
			return err
		}
	}
	return nil
}

// Enhanced entry processing with user management
func (e Entry) ProcessWithAuth() error {
	parsers := make(map[string]Parser)
	parsers["birth"] = &BirthMessage{}
	parsers["death"] = &DeathMessage{}
	parsers["rain"] = &RainMessage{}
	parsers["temperature"] = &TemperatureMessage{}
	parsers["weather"] = &WeatherMessage{}

	for _, change := range e.Changes {
		name := "unknown"
		phoneNumber := ""

		for _, contact := range change.Value.Contacts {
			name = contact.Profile.Name
			phoneNumber = contact.WaID
		}

		// Auto-register user if they don't exist
		if phoneNumber != "" {
			user, err := AutoRegisterFromWhatsApp(phoneNumber, name)
			if err != nil {
				return err
			}
			// User is now registered and can use the system
			_ = user
		}

		for _, message := range change.Value.Messages {
			// Rest of existing message processing...
			timestamp, err := strconv.ParseInt(message.Timestamp, 10, 64)
			if err != nil {
				now := time.Now()
				timestamp = now.Unix()
			}

			unixTimestamp := int64(timestamp)
			t := time.Unix(unixTimestamp, 0)

			baseMessageValues := &BaseMessageValues{
				EntryID:     e.ID,
				MessageID:   message.ID,
				PhoneNumber: message.From,
				Name:        name,
				Date:        t.Format(time.RFC3339),
			}

			for _, parser := range parsers {
				if found := parser.Parse(message.Text.Body); found {
					if err := parser.Insert(baseMessageValues); err != nil {
						fmt.Printf("Error insert record into DB: %v\n", err)
					}
					text := textmsg.NewMessageSender(message.From, parser.Text())
					if err := text.Send(); err != nil {
						fmt.Printf("Error replying: %v\n", err)
					}
				}
			}
		}
	}
	return nil
}

// HTTP request handler for authentication endpoints
func handleHTTPRequest(httpData interface{}) Response {
	httpMap, ok := httpData.(map[string]interface{})
	if !ok {
		return FunctionError("invalid_http_data")
	}

	method, _ := httpMap["method"].(string)
	path, _ := httpMap["path"].(string)
	body, _ := httpMap["body"].(string)

	// Connect to database
	dbConnect()
	defer dbConn.Disconnect(context.TODO())

	// Create router
	router := mux.NewRouter()
	
	// Authentication routes
	router.HandleFunc("/auth/register", HandleRegister).Methods("POST")
	router.HandleFunc("/auth/login", HandleLogin).Methods("POST")
	router.HandleFunc("/auth/verify-email", HandleEmailVerification).Methods("POST")
	router.HandleFunc("/auth/link-phone", AuthMiddleware(HandleLinkPhoneNumber)).Methods("POST")
	
	// Protected dashboard routes
	router.HandleFunc("/api/user/profile", AuthMiddleware(HandleUserProfile)).Methods("GET")
	router.HandleFunc("/api/user/ranches", AuthMiddleware(HandleUserRanches)).Methods("GET")
	
	// Existing data routes with authentication
	router.HandleFunc("/data/{datatype}/{phonenumber}", AuthMiddleware(HandleDataWithAuth)).Methods("GET")
	router.HandleFunc("/data/download/{datatype}/{phonenumber}", AuthMiddleware(HandleDownloadWithAuth)).Methods("GET")

	// Create HTTP request
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	
	// Add authorization header if present
	if auth, exists := httpMap["authorization"].(string); exists {
		req.Header.Set("Authorization", auth)
	}

	rsp := httptest.NewRecorder()
	router.ServeHTTP(rsp, req)

	httpResponse := rsp.Result()
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return FunctionError(err)
	}

	return Response{
		Body:       string(responseBody),
		StatusCode: strconv.Itoa(httpResponse.StatusCode),
		Headers:    httpResponse.Header,
	}
}

// User profile handler
func HandleUserProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)
	
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	collection := dbConn.Database("mydatabase").Collection("users")
	var user User
	err = collection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Clear password
	user.Password = ""
	json.NewEncoder(w).Encode(user)
}

// User ranches handler
func HandleUserRanches(w http.ResponseWriter, r *http.Request) {
	phoneNumber := r.Context().Value("phone_number").(string)
	
	// Get user's ranch data
	collection := dbConn.Database("mydatabase").Collection("ranches")
	cursor, err := collection.Find(context.TODO(), bson.M{"phone": phoneNumber})
	if err != nil {
		http.Error(w, "Error fetching ranches", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var ranches []bson.M
	if err = cursor.All(context.TODO(), &ranches); err != nil {
		http.Error(w, "Error processing ranches", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ranches": ranches,
		"count":   len(ranches),
	})
}

// Enhanced data handler with authentication
func HandleDataWithAuth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	datatype := vars["datatype"]
	phoneNumber := vars["phonenumber"]
	
	// Verify user has access to this phone number's data
	userPhone := r.Context().Value("phone_number").(string)
	if userPhone != phoneNumber {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Use existing data handler logic
	data, err := dbReadUnordered(datatype, phoneNumber)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, string(jsonData))
}

// Enhanced download handler with authentication
func HandleDownloadWithAuth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	datatype := vars["datatype"]
	phoneNumber := vars["phonenumber"]
	
	// Verify user has access to this phone number's data
	userPhone := r.Context().Value("phone_number").(string)
	if userPhone != phoneNumber {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Use existing download handler logic
	data, err := dbReadOrdered(datatype, phoneNumber)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return
	}

	csv, err := ConvertBsonToCsv(data)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%v", err)
		return
	}

	length := strconv.Itoa(len(csv))
	disposition := fmt.Sprintf("attachment; filename=\"%s.csv\"", datatype)
	w.Header().Add("Content-Type", "text/csv")
	w.Header().Add("Content-Length", length)
	w.Header().Add("Content-Disposition", disposition)
	fmt.Fprint(w, csv)
}

// Error response helper
func FunctionError(err interface{}) Response {
	body := fmt.Sprintf("%v", err)
	return Response{
		Body:       body,
		StatusCode: "400",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
}

// Success response helper
func FunctionSuccess(body interface{}) Response {
	return Response{
		Body:       fmt.Sprintf("%v", body),
		StatusCode: "200",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
}
