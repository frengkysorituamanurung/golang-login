package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// DB adalah variabel global untuk koneksi database.
var DB *sql.DB

// User adalah struktur untuk data pengguna.
type User struct {
	ID       int
	Username string
	Password string
}

func main() {
	// Koneksi ke database MySQL.
	db, err := sql.Open("mysql", "username:password@tcp(127.0.0.1:3306)/dbname")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	DB = db

	// Membuat tabel pengguna jika belum ada.
	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		password VARCHAR(200) NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("Server berjalan di http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Selamat datang di halaman utama")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Gagal mengenkripsi kata sandi", http.StatusInternalServerError)
			return
		}

		_, err = DB.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
		if err != nil {
			mysqlErr, ok := err.(*mysql.MySQLError)
			if ok && mysqlErr.Number == 1062 {
				http.Error(w, "Username sudah digunakan", http.StatusBadRequest)
				return
			}
			http.Error(w, "Gagal membuat pengguna", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("register.html"))
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedPassword string
		err := DB.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Pengguna tidak ditemukan", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Gagal mengambil data pengguna", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Kata sandi salah", http.StatusUnauthorized)
			return
		}

		// Berhasil login, atur sesi atau cookie sesuai kebutuhan aplikasi Anda.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("login.html"))
	tmpl.Execute(w, nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Handle logout logic here (e.g., clearing session, cookies, etc.).
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
