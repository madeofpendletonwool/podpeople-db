package models

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

// CheckPassword checks if the provided password matches the stored hash
func (a *Admin) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(a.Password), []byte(password))
	return err == nil
}

// SetPassword securely hashes and sets the password
func (a *Admin) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.Password = string(hashedPassword)
	return nil
}

// FindByID finds an admin by ID
func (a *Admin) FindByID(db *sql.DB, id int) error {
	return db.QueryRow("SELECT id, username, password FROM admins WHERE id = ?", id).
		Scan(&a.ID, &a.Username, &a.Password)
}

// FindByUsername finds an admin by username
func (a *Admin) FindByUsername(db *sql.DB, username string) error {
	return db.QueryRow("SELECT id, username, password FROM admins WHERE username = ?", username).
		Scan(&a.ID, &a.Username, &a.Password)
}

// Create creates a new admin in the database
func (a *Admin) Create(db *sql.DB) error {
	result, err := db.Exec("INSERT INTO admins (username, password) VALUES (?, ?)",
		a.Username, a.Password)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	a.ID = int(id)
	return nil
}

// Update updates an admin's details in the database
func (a *Admin) Update(db *sql.DB) error {
	_, err := db.Exec("UPDATE admins SET username = ?, password = ? WHERE id = ?",
		a.Username, a.Password, a.ID)
	return err
}

// Delete deletes an admin from the database
func (a *Admin) Delete(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM admins WHERE id = ?", a.ID)
	return err
}

// CountAdmins counts the total number of admins in the database
func CountAdmins(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	return count, err
}

// GetAllAdmins gets all admins from the database
func GetAllAdmins(db *sql.DB) ([]Admin, error) {
	rows, err := db.Query("SELECT id, username FROM admins ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var admins []Admin
	for rows.Next() {
		var admin Admin
		if err := rows.Scan(&admin.ID, &admin.Username); err != nil {
			return nil, err
		}
		admins = append(admins, admin)
	}

	return admins, nil
}
