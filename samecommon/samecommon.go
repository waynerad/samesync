package samecommon

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"os"
)

const RoleAdmin = 1
const RoleSyncPointUser = 2

const AccessRead = 1
const AccessWrite = 2

type AuthInfo struct {
	UserId int64
	Role   int
}

type ListUserInfo struct {
	Username string
	Role     int
}

type ListSyncPointInfo struct {
	PublicId string
	Path     string
}

type ListGrantInfo struct {
	Username string
	PublicId string
	Access   int
}

// we don't use fileSize but we're including it here to make this definition identical with the client
type SameFileInfo struct {
	FilePath   string
	FileSize   int64
	FileTime   int64
	FileHash   string
	ReUpNeeded bool
}

// Most of these "generate" functions all do the same thing --
// generate 32 bytes. But they're all separate functions, because
// conceptually they generate different things.

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func GenerateSHAKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func GenerateAESInitializationVector() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

func RoleFlagsToString(roleflags int) string {
	result := ""
	if roleflags == 0 {
		return result
	}
	if (roleflags & RoleAdmin) != 0 {
		result += ", Admin"
	}
	if (roleflags & RoleSyncPointUser) != 0 {
		result += ", Sync point user"
	}
	return result[2:]
}

func AccessFlagsToString(access int) string {
	result := ""
	if access == 0 {
		return result
	}
	if access == AccessRead {
		return "Read Only"
	}
	if access == AccessWrite {
		return "Write Only"
	}
	if (access & AccessRead) != 0 {
		result += ", Read"
	}
	if (access & AccessWrite) != 0 {
		result += ", Write"
	}
	return result[2:]
}

func SetNameValuePair(db *sql.DB, name string, value string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "SELECT nvpairid FROM settings WHERE name = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err := stmtSelExisting.Query(name)
	if err != nil {
		return err
	}
	defer rowsExisting.Close()
	var nvpairid int64
	nvpairid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&nvpairid)
		if err != nil {
			return err
		}
	}
	if nvpairid == 0 {
		cmd = "INSERT INTO settings (name, value) VALUES (?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return err
		}
		_, err = stmtIns.Exec(name, value)
		if err != nil {
			return err
		}
	} else {
		cmd = "UPDATE settings SET value = ? WHERE nvpairid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(value, nvpairid)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func GetValue(db *sql.DB, name string, defval string) (string, error) {
	var value string
	value = defval
	cmd := "SELECT value FROM settings WHERE name = ?;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return "", err
	}
	rows, err := stmtSel.Query(name)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		err = rows.Scan(&value)
		if err != nil {
			return "", err
		}
	}
	return value, nil
}

// This function converts all path separators to whatever our actual OS uses
func MakePathSeparatorsForThisOS(filepath string) string {
	asbytes := []byte(filepath)
	lasb := len(asbytes)
	for ii := 0; ii < lasb; ii++ {
		if (asbytes[ii] == '/') || (asbytes[ii] == '\\') {
			asbytes[ii] = os.PathSeparator
		}
	}
	return string(asbytes)
}

// This function converts all path separators to a stardard form
// (forward slash) for us to store in the database.
// Having a standard form means it will match requests correctly
// no matter what OS the client is using.
func MakePathSeparatorsStandard(filepath string) string {
	asbytes := []byte(filepath)
	lasb := len(asbytes)
	for ii := 0; ii < lasb; ii++ {
		if asbytes[ii] == '\\' {
			asbytes[ii] = '/'
		}
	}
	return string(asbytes)
}

// This function converts all path separators to whatever our actual OS uses
// Path must use current OS path separators or this won't work.
func MakePathForFile(filepath string) error {
	last := -1
	lfp := len(filepath)
	for ii := 0; ii < lfp; ii++ {
		if filepath[ii] == os.PathSeparator {
			last = ii
		}
	}
	if last <= 0 {
		return nil
	}
	return os.MkdirAll(filepath[:last], 0777)
}

func FileExists(filepath string) (bool, error) {
	fhFile, err := os.Open(MakePathSeparatorsForThisOS(filepath))
	if err != nil {
		message := err.Error()
		if message[len(message)-25:] == "no such file or directory" {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	err = fhFile.Close()
	return true, err
}

func CalculatePwHash(pwsalt []byte, password string) []byte {
	combo := append(pwsalt, []byte(password)...)
	sum := sha256.Sum256([]byte(combo))
	result := make([]byte, 32)
	// copy(result,sum) -- gives error second argument to copy should be slice or string; have [32]byte
	for ii := 0; ii < 32; ii++ {
		result[ii] = sum[ii]
	}
	return result
}
