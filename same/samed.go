package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"wrpc"
)

const roleAdmin = 1
const roleSyncPointUser = 2

const accessRead = 1
const accessWrite = 2

const databaseFileName = "sameserver.db"

type authinfo struct {
	userid int64
	role   int
}

type listUserInfo struct {
	email string
	role  int
}

type listSyncPointInfo struct {
	publicid string
	path     string
}

type listGrantInfo struct {
	email    string
	publicid string
	access   int
}

// we don't use fileSize but we're including it here to make this definition identical with the client
type wfileInfo struct {
	filePath   string
	fileSize   int64
	fileTime   int64
	fileHash   string
	reupNeeded bool
}

func intToStr(ii int) string {
	return strconv.FormatInt(int64(ii), 10)
}

func strToInt(stg string) int {
	ii, err := strconv.ParseInt(stg, 10, 64)
	if err != nil {
		return 0
	}
	return int(ii)
}

func onOff(bv bool) string {
	if bv {
		return "ON"
	} else {
		return "OFF"
	}
}

// Most of these "generate" functions all do the same thing --
// generate 32 bytes. But they're all separate functions, because
// conceptually they generate different things.

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func generateSHAKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func generatePassword() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	password := make([]byte, 99)
	num := ascii85.Encode(password, key)
	return string(password[:num]), err
}

func generatePwSalt() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func calculatePwHash(pwsalt []byte, password string) []byte {
	combo := append(pwsalt, []byte(password)...)
	sum := sha256.Sum256([]byte(combo))
	result := make([]byte, 32)
	// copy(result,sum) -- gives error second argument to copy should be slice or string; have [32]byte
	for ii := 0; ii < 32; ii++ {
		result[ii] = sum[ii]
	}
	return result
}

func generateSyncPointId() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func roleFlagsToString(roleflags int) string {
	result := ""
	if roleflags == 0 {
		return result
	}
	if (roleflags & roleAdmin) != 0 {
		result += ", Admin"
	}
	if (roleflags & roleSyncPointUser) != 0 {
		result += ", Sync point user"
	}
	return result[2:]
}

func accessFlagsToString(access int) string {
	result := ""
	if access == 0 {
		return result
	}
	if access == accessRead {
		return "Read Only"
	}
	if access == accessWrite {
		return "Write Only"
	}
	if (access & accessRead) != 0 {
		result += ", Read"
	}
	if (access & accessWrite) != 0 {
		result += ", Write"
	}
	return result[2:]
}

func setNameValuePair(db *sql.DB, name string, value string, verbose bool, protectExistingValue bool) error {
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
		if protectExistingValue {
			err := tx.Rollback()
			return err
		}
		cmd = "UPDATE settings SET value = ? WHERE nvpairid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(value, nvpairid)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	if verbose {
		fmt.Println("Set configuration setting:", name, "=", value)
	}
	return err
}

func getValue(db *sql.DB, name string, defval string, verbose bool) (string, error) {
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
	if verbose {
		fmt.Println(name, "=", value)
	}
	return value, nil
}

func initializeSettings(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	cmd := "CREATE TABLE settings (nvpairid INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(255) NOT NULL, value VARCHAR(255) NOT NULL);"
	stmtCreate, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtCreate.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_sett_nm ON settings (name);"
	stmtIndex, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	err = tx.Commit()
	return err
}

func initializeServerTables(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "CREATE TABLE syncpoint (syncptid INTEGER PRIMARY KEY AUTOINCREMENT, publicid TEXT NOT NULL, path TEXT NOT NULL);"
	stmtCreate, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtCreate.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_sh_pi ON syncpoint (publicid);"
	stmtIndex, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_sh_pa ON syncpoint (path);"
	stmtIndex, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE TABLE user (userid INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, pwsalt TEXT NOT NULL, pwhash TEXT NOT NULL, role INTEGER);"
	stmtCreate, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtCreate.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_us_em ON user (email);"
	stmtIndex, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE TABLE grant (grantid INTEGER PRIMARY KEY AUTOINCREMENT, syncptid INTEGER NOT NULL, userid INTEGER NOT NULL, access INTEGER NOT NULL);"
	stmtCreate, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtCreate.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_su_sp ON grant (syncptid);"
	stmtIndex, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_su_ur ON grant (userid);"
	stmtIndex, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE TABLE fileinfo (fileid INTEGER PRIMARY KEY AUTOINCREMENT, syncptid INTEGER NOT NULL, filepath TEXT NOT NULL, modtime INTEGER NOT NULL, filehash TEXT NOT NULL, reupneeded INTEGER NOT NULL);"
	stmtCreate, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtCreate.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_file_pth ON fileinfo (syncptid, filepath);"
	stmtIndex, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtIndex.Exec()
	if err != nil {
		return err
	}
	err = tx.Commit()
	return err
}

func createTheAdminAccount(db *sql.DB, verbose bool) error {
	fmt.Println("Creating admin account.")
	email := "admin"
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "SELECT userid FROM user WHERE email = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err := stmtSelExisting.Query(email)
	if err != nil {
		return err
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return err
		}
	}
	password, err := generatePassword()
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			return err2
		} else {
			return err
		}
	}
	pwSaltBin, err := generatePwSalt()
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			return err2
		} else {
			return err
		}
	}
	pwsalt := hex.EncodeToString(pwSaltBin)
	pwHashBin := calculatePwHash(pwSaltBin, password)
	pwhash := hex.EncodeToString(pwHashBin)
	role := roleAdmin
	if userid == 0 {
		cmd = "INSERT INTO user (email, pwsalt, pwhash, role) VALUES (?, ?, ?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return err
		}
		_, err = stmtIns.Exec(email, pwsalt, pwhash, role)
		if err != nil {
			return err
		}
		if verbose {
			fmt.Println("    Admin account created.")
		}
	} else {
		cmd = "UPDATE user SET email = ?, pwsalt = ?, pwhash = ?, role = ? WHERE userid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(email, pwsalt, pwhash, role, userid)
		if err != nil {
			return err
		}
		if verbose {
			fmt.Println("    Admin account already exists.")
			fmt.Println("    Admin account reset.")
		}
	}
	err = tx.Commit()
	if verbose {
		fmt.Println("    Admin account created:")
		fmt.Println("        username (email): ", email)
		fmt.Println("        password: ", password)
		fmt.Println("        password salt: ", pwsalt)
		fmt.Println("        password hash: ", pwhash)
		fmt.Println("        role: ", roleFlagsToString(role))
	}
	fmt.Println(password)
	return err
}

func isDirEmpty(path string, verbose bool) (bool, error) {
	if verbose {
		fmt.Println("Checking to see if", path, "is empty.")
	}
	dir, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	filesInDir, err := dir.Readdir(0)
	if err != nil {
		return false, err
	}
	if len(filesInDir) == 0 {
		return true, nil
	}
	return false, nil
}

func determineAccessForSyncPoint(verbose bool, db *sql.DB, auth *authinfo, syncpublicid string, accessRequested int) (int64, string, error) {
	if verbose {
		fmt.Println("Checking access for: userid", auth.userid, "sync point public ID", syncpublicid, "with requested access flags", accessFlagsToString(accessRequested))
	}
	if auth.userid == 0 {
		return 0, "", errors.New("Access denied: not logged in.")
	}
	if (auth.role & roleSyncPointUser) == 0 {
		return 0, "", errors.New("Access denied: User does not have " + `"` + "SyncPointUser" + `"` + " role.")
	}
	cmd := "SELECT syncptid, path FROM syncpoint WHERE publicid = ?;"

	stmtSelSyncPoint, err := db.Prepare(cmd)
	if err != nil {
		return 0, "", errors.New("determineAccessForSyncPoint: " + err.Error())
	}
	rowsSyncPoint, err := stmtSelSyncPoint.Query(syncpublicid)
	if err != nil {
		return 0, "", errors.New("determineAccessForSyncPoint: " + err.Error())
	}
	defer rowsSyncPoint.Close()
	var syncptid int64
	syncptid = 0
	var path string
	for rowsSyncPoint.Next() {
		err = rowsSyncPoint.Scan(&syncptid, &path)
		if err != nil {
			return 0, "", errors.New("determineAccessForSyncPoint: " + err.Error())
		}
	}
	if syncptid == 0 {
		return 0, "", errors.New("Sync point " + `"` + syncpublicid + `"` + " not found.")
	}

	cmd = "SELECT grantid, access FROM grant WHERE (syncptid = ?) AND (userid = ?);"

	stmtSelGrant, err := db.Prepare(cmd)
	if err != nil {
		return 0, "", errors.New("determineAccessForSyncPoint: " + err.Error())
	}
	rowsGrant, err := stmtSelGrant.Query(syncptid, auth.userid)
	if err != nil {
		return 0, "", errors.New("determineAccessForSyncPoint: " + err.Error())
	}
	defer rowsGrant.Close()
	var grantid int64
	grantid = 0
	var access int
	for rowsGrant.Next() {
		err = rowsGrant.Scan(&grantid, &access)
		if err != nil {
			return 0, "", errors.New("determineAccessForSyncPoint: " + err.Error())
		}
	}
	if grantid == 0 {
		return syncptid, path, errors.New("Access denied: No grants found for sync point " + `"` + syncpublicid + `"` + ".")
	}
	if (access & accessRequested) == accessRequested {
		return syncptid, path, nil
	}
	return syncptid, path, errors.New("Access denied. No access grant for requested access:" + accessFlagsToString(accessRequested))
}

// This function converts all path separators to whatever our actual OS uses
func makePathSeparatorsForThisOS(filepath string) string {
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
func makePathSeparatorsStandard(filepath string) string {
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
func makePathForFile(filepath string) error {
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

func stashFileInfo(db *sql.DB, syncptid int64, filepath string, modtime int64, filehash string) error {
	filepath = makePathSeparatorsStandard(filepath)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "SELECT fileid FROM fileinfo WHERE (syncptid = ?) AND (filepath = ?);"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err := stmtSelExisting.Query(syncptid, filepath)
	if err != nil {
		return err
	}
	defer rowsExisting.Close()
	var fileid int64
	fileid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&fileid)
		if err != nil {
			return err
		}
	}
	if fileid == 0 {
		cmd = "INSERT INTO fileinfo (syncptid, filepath, modtime, filehash, reupneeded) VALUES (?, ?, ?, ?, 0);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return err
		}
		_, err = stmtIns.Exec(syncptid, filepath, modtime, filehash)
		if err != nil {
			return err
		}
	} else {
		cmd = "UPDATE fileinfo SET modtime = ?, filehash = ?, reupneeded = 0 WHERE fileid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(modtime, filehash, fileid)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func getFileInfo(db *sql.DB, syncptid int64, filepath string) (int64, int64, string, error) {
	filepath = makePathSeparatorsStandard(filepath)
	cmd := "SELECT fileid, modtime, filehash FROM fileinfo WHERE (syncptid = ?) AND (filepath = ?);"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return 0, 0, "", err
	}
	rows, err := stmtSel.Query(syncptid, filepath)
	if err != nil {
		return 0, 0, "", err
	}
	defer rows.Close()
	var fileid int64
	fileid = 0
	var modtime int64
	var filehash string
	for rows.Next() {
		err = rows.Scan(&fileid, &modtime, &filehash)
		if err != nil {
			return 0, 0, "", err
		}
	}
	if fileid == 0 {
		return 0, 0, "", errors.New("Could not find file: " + `"` + filepath + `"`)
	}
	return fileid, modtime, filehash, nil
}

// need this function to handle nils
func errorToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func markFileAsReuploadneeded(db *sql.DB, fileid int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "UPDATE fileinfo SET reupneeded = 1 WHERE fileid = ?;"
	stmtUpd, err := tx.Prepare(cmd)
	_, err = stmtUpd.Exec(fileid)
	if err != nil {
		return err
	}
	err = tx.Commit()
	return err
}

// ----------------------------------------------------------------
// functions callable remotely
// ----------------------------------------------------------------

func getTime() int64 {
	now := time.Now()
	result := now.UnixNano()
	return result
}

func receiveFile(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *authinfo, syncpublicid string, filepath string, size int64, modtime int64, filehash string) (string, error) {
	version := 0
	fmt.Println("Receiving file:", filepath)
	//
	// Step 1: Check permissions
	if (auth.role & roleSyncPointUser) == 0 {
		wnet.Close()
		return "", errors.New("Permission denied: User is not assigned to the sync point user role.")
	}
	syncptid, localpath, err := determineAccessForSyncPoint(verbose, db, auth, syncpublicid, accessWrite)
	if err != nil {
		return "", err
	}
	//
	// Step 2: Send "Go ahead and send" message.
	// Without this go-ahead, the client will not send us the bytes.
	err = wrpc.SendReplyScalarString("ReceiveFile", version, "GoAheadAndSend", "", wnet)
	if err != nil {
		return "", err
	}
	//
	// Step 3: Actually receive the bytes of the file
	// While the reply is headed out, we go ahead and start reading
	// the actual file bytes coming in
	var fhOut *os.File
	fhOut, err = os.Create(localpath + string(os.PathSeparator) + "temp.temp")
	if err != nil {
		return "", errors.New("receiveFile: file create: " + err.Error())
	}
	var bytesread int64
	bytesread = 0
	const bufferSize = 65536
	// const bufferSize = 32768
	buffer := make([]byte, bufferSize)
	ciphertext := make([]byte, bufferSize)
	var nIn int
	var nOut int
	for bytesread < size {
		lrest := size - bytesread
		if lrest > bufferSize {
			nIn, err = wnet.PullBytes(buffer, ciphertext)
		} else {
			nIn, err = wnet.PullBytes(buffer[:lrest], ciphertext[:lrest])
		}
		if err != nil {
			return "", errors.New("receiveFile: PullBytes: " + err.Error())
		}
		nOut, err = fhOut.Write(buffer[:nIn])
		if err != nil {
			return "", errors.New("receiveFile: Write bytes to file:" + err.Error())
		}
		if nOut != nIn {
			return "", errors.New("Could no write entire buffer out to file for some unknown reason.")
		}
		bytesread += int64(nIn)
	}
	fhOut.Close()
	//
	// Step 4: Rename the file to slot it in place, replacing the
	// existing file, which we have preserved until now in case
	// anything went wrong.
	err = os.Rename(localpath+string(os.PathSeparator)+"temp.temp", localpath+makePathSeparatorsForThisOS(filepath))
	if err != nil {
		mkerr := makePathForFile(localpath + makePathSeparatorsForThisOS(filepath))
		if mkerr != nil {
			return "", errors.New("receiveFile: make path: " + err.Error())
		}
		mverr := os.Rename(localpath+string(os.PathSeparator)+"temp.temp", localpath+makePathSeparatorsForThisOS(filepath))
		if mverr != nil {
			return "", errors.New("receiveFile: rename: " + err.Error())
		}
	}
	//
	// Step 5: Stash all the info about the file in our server database
	err = stashFileInfo(db, syncptid, filepath, modtime, filehash)
	if err != nil {
		return "", errors.New("receiveFile: stash file info: " + err.Error())
	}
	//
	// Step 6: Return "Reception complete" message which will be sent back to the client as the reply
	return "ReceptionComplete", nil
}

func login(db *sql.DB, auth *authinfo, verbose bool, email string, password string) error {
	if verbose {
		fmt.Println("Logging in as email", email, "password", password)
	}
	cmd := "SELECT userid, pwsalt, pwhash, role FROM user WHERE email = ?;"
	stmtSelExisting, err := db.Prepare(cmd)
	if err != nil {
		return errors.New("login: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(email)
	if err != nil {
		return errors.New("login: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	var pwsalt string
	var pwhash string
	var role int
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid, &pwsalt, &pwhash, &role)
		if err != nil {
			return errors.New("login: " + err.Error())
		}
	}
	if userid == 0 {
		return errors.New("Email " + `"` + email + `"` + " not found.")
	}
	pwSaltBin, err := hex.DecodeString(pwsalt)
	if err != nil {
		return errors.New("login: " + err.Error())
	}
	pwHashBin1 := calculatePwHash(pwSaltBin, password)
	pwHashBin2, err := hex.DecodeString(pwhash)
	if err != nil {
		return errors.New("login: " + err.Error())
	}
	if subtle.ConstantTimeCompare(pwHashBin1, pwHashBin2) == 1 {
		auth.userid = userid
		auth.role = role
		if verbose {
			fmt.Println("    Logged in as email", email, "userid", userid, "role flags:", roleFlagsToString(role))
		}
		return nil
	}
	if verbose {
		fmt.Println("    Incorrect password.")
	}
	return errors.New("Incorrect password.")
}

func listUsers(db *sql.DB, auth *authinfo) ([]listUserInfo, error) {
	if (auth.role & roleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	result := make([]listUserInfo, 0)
	cmd := "SELECT email, role FROM user WHERE 1 ORDER BY email;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return result, errors.New("listUsers: " + err.Error())
	}
	rows, err := stmtSel.Query()
	if err != nil {
		return result, errors.New("listUsers: " + err.Error())
	}
	var email string
	var role int
	for rows.Next() {
		err = rows.Scan(&email, &role)
		if err != nil {
			return result, errors.New("listUsers: " + err.Error())
		}
		result = append(result, listUserInfo{email, role})
	}
	return result, nil
}

func addUser(verbose bool, db *sql.DB, auth *authinfo, email string, role int) (string, error) {
	if verbose {
		fmt.Println("Attempting to add User " + email + " added with role:" + roleFlagsToString(role))
	}
	if (auth.role & roleAdmin) == 0 {
		return "", errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return "", errors.New("addUser: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE email = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return "", errors.New("addUser: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(email)
	if err != nil {
		return "", errors.New("addUser: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
	}
	var password string
	if userid == 0 {
		password, err = generatePassword()
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return "", errors.New("addUser: " + err2.Error())
			} else {
				return "", errors.New("addUser: " + err.Error())
			}
		}
		pwSaltBin, err := generatePwSalt()
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return "", errors.New("addUser: " + err2.Error())
			} else {
				return "", errors.New("addUser: " + err.Error())
			}
		}
		pwsalt := hex.EncodeToString(pwSaltBin)
		pwHashBin := calculatePwHash(pwSaltBin, password)
		pwhash := hex.EncodeToString(pwHashBin)
		cmd = "INSERT INTO user (email, pwsalt, pwhash, role) VALUES (?, ?, ?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return "", errors.New("addUser: " + err2.Error())
			} else {
				return "", errors.New("addUser: " + err.Error())
			}
		}
		_, err = stmtIns.Exec(email, pwsalt, pwhash, role)
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return "", errors.New("addUser: " + err2.Error())
			} else {
				return "", errors.New("addUser: " + err.Error())
			}
		}
		if verbose {
			fmt.Println("    User does not exist, will be added")
		}
	} else {
		err := tx.Rollback()
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
		if verbose {
			fmt.Println("    User already exists")
		}
		return "", errors.New("addUser: User already exists.")
	}
	err = tx.Commit()
	if err != nil {
		return password, errors.New("addUser: " + err.Error())
	}
	if verbose {
		fmt.Println("    User " + email + " added with role:" + roleFlagsToString(role))
	}
	return password, nil
}

func addSyncPoint(verbose bool, db *sql.DB, auth *authinfo, path string) (string, error) {
	if verbose {
		fmt.Println("Adding sync point with path", path)
	}
	if (auth.role & roleAdmin) == 0 {
		return "", errors.New("Permission denied: User is not assigned to the admin role.")
	}
	if len(path) == 0 {
		return "", errors.New("No path specified.")
	}
	if path[0] != os.PathSeparator {
		return "", errors.New("Must be an absolute path.")
	}
	dirEmpty, err := isDirEmpty(path, verbose)
	if err != nil {
		return "", err
	}
	if !dirEmpty {
		return "", errors.New("Directory is not empty")
	}
	tx, err := db.Begin()
	if err != nil {
		return "", errors.New("addUser: " + err.Error())
	}
	cmd := "SELECT syncptid FROM syncpoint WHERE path = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return "", errors.New("addUser: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(path)
	if err != nil {
		return "", errors.New("addUser: " + err.Error())
	}
	defer rowsExisting.Close()
	var syncptid int64
	syncptid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&syncptid)
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
	}
	var publicid string
	if syncptid == 0 {
		publicIdBin, err := generateSyncPointId()
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
		publicid = hex.EncodeToString(publicIdBin)
		cmd = "INSERT INTO syncpoint (publicid, path) VALUES (?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
		_, err = stmtIns.Exec(publicid, path)
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
	} else {
		err = tx.Rollback()
		if err != nil {
			return "", errors.New("addUser: " + err.Error())
		}
		return "", errors.New("Sync point already exists.")
	}
	err = tx.Commit()
	if err != nil {
		return publicid, errors.New("addUser: " + err.Error())
	}
	if verbose {
		fmt.Println("    Sync point created with path:", path)
		fmt.Println("    Public ID:", publicid)
	}
	return publicid, nil
}

func listSyncPoints(db *sql.DB, auth *authinfo) ([]listSyncPointInfo, error) {
	if (auth.role & roleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	result := make([]listSyncPointInfo, 0)
	cmd := "SELECT publicid, path FROM syncpoint WHERE 1 ORDER BY path;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return result, errors.New("listSyncPoints: " + err.Error())
	}
	rows, err := stmtSel.Query()
	if err != nil {
		return result, errors.New("listSyncPoints: " + err.Error())
	}
	var publicid string
	var path string
	for rows.Next() {
		err = rows.Scan(&publicid, &path)
		if err != nil {
			return result, errors.New("listSyncPoints: " + err.Error())
		}
		result = append(result, listSyncPointInfo{publicid, path})
	}
	return result, nil
}

func addGrant(verbose bool, db *sql.DB, auth *authinfo, email string, syncpublicid string, access int) error {
	if verbose {
		fmt.Println("Granting access to sync point for user.")
		fmt.Println("    Email:", email)
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	if (auth.role & roleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE email = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(email)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
	}
	if userid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
		return errors.New("Email " + `"` + email + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found email.")
	}
	cmd = "SELECT syncptid FROM syncpoint WHERE publicid = ?;"
	stmtSelExisting, err = tx.Prepare(cmd)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	rowsExisting, err = stmtSelExisting.Query(syncpublicid)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	defer rowsExisting.Close()
	var syncptid int64
	syncptid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&syncptid)
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
	}
	if syncptid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
		return errors.New("Share point ID " + `"` + syncpublicid + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found share point ID.")
	}
	cmd = "SELECT grantid FROM grant WHERE (syncptid = ?) AND (userid = ?);"
	stmtSelExisting, err = tx.Prepare(cmd)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	rowsExisting, err = stmtSelExisting.Query(syncptid, userid)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	defer rowsExisting.Close()
	var grantid int64
	grantid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&grantid)
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
	}
	if grantid == 0 {
		if verbose {
			fmt.Println("    User is not granted access to sync point. Creating access now.")
		}
		cmd = "INSERT INTO grant (syncptid, userid, access) VALUES (?, ?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
		_, err = stmtIns.Exec(syncptid, userid, access)
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
	} else {
		if verbose {
			fmt.Println("    User is already granted access to sync point. Updating access flags.")
		}
		cmd = "UPDATE grant SET access = ? WHERE grantid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(access, grantid)
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
	}
	err = tx.Commit()
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	if verbose {
		fmt.Println("    User granted access to share.")
	}
	return nil
}

func listGrants(db *sql.DB, auth *authinfo) ([]listGrantInfo, error) {
	if (auth.role & roleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	result := make([]listGrantInfo, 0)
	cmd := "SELECT user.email, syncpoint.publicid, grant.access FROM user, grant, syncpoint WHERE (user.userid = grant.userid) AND (grant.syncptid = syncpoint.syncptid) ORDER BY user.email;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return result, errors.New("listGrants: " + err.Error())
	}
	rows, err := stmtSel.Query()
	if err != nil {
		return result, errors.New("listGrants: " + err.Error())
	}
	var email string
	var publicid string
	var access int
	for rows.Next() {
		err = rows.Scan(&email, &publicid, &access)
		if err != nil {
			return result, errors.New("listGrants: " + err.Error())
		}
		result = append(result, listGrantInfo{email, publicid, access})
	}
	return result, nil
}

func deleteGrant(verbose bool, db *sql.DB, auth *authinfo, email string, syncpublicid string) error {
	if verbose {
		fmt.Println("Revoking access to sync point for user.")
		fmt.Println("    Email:", email)
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	if (auth.role & roleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE email = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(email)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
	}
	if userid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
		return errors.New("Email " + `"` + email + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found email.")
	}
	cmd = "SELECT syncptid FROM syncpoint WHERE publicid = ?;"
	stmtSelExisting, err = tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	rowsExisting, err = stmtSelExisting.Query(syncpublicid)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	defer rowsExisting.Close()
	var syncptid int64
	syncptid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&syncptid)
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
	}
	if syncptid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
		return errors.New("Share point ID " + `"` + syncpublicid + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found share point ID")
	}
	cmd = "SELECT grantid FROM grant WHERE (syncptid = ?) AND (userid = ?);"
	stmtSelExisting, err = tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	rowsExisting, err = stmtSelExisting.Query(syncptid, userid)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	defer rowsExisting.Close()
	var grantid int64
	grantid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&grantid)
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
	}
	if grantid == 0 {
		if verbose {
			fmt.Println("    User is not granted access to sync point.")
		}
		err = tx.Rollback()
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
		return errors.New("User " + `"` + email + `"` + " does not have access to " + `"` + syncpublicid + `"` + ".")
	} else {
		if verbose {
			fmt.Println("    User is granted access to sync point. Revoking access.")
		}
		cmd = "DELETE FROM grant WHERE grantid = ?;"
		stmtDel, err := tx.Prepare(cmd)
		_, err = stmtDel.Exec(grantid)
		if err != nil {
			return errors.New("deleteGrant: " + err.Error())
		}
	}
	err = tx.Commit()
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	if verbose {
		fmt.Println("    Access to share revoked.")
	}
	return nil
}

func deleteSyncPoint(verbose bool, db *sql.DB, auth *authinfo, syncpublicid string) error {
	if verbose {
		fmt.Println("Deleting sync point")
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	if (auth.role & roleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("deleteSyncPoint: " + err.Error())
	}
	cmd := "SELECT syncptid FROM syncpoint WHERE publicid = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteSyncPoint: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(syncpublicid)
	if err != nil {
		return errors.New("deleteSyncPoint: " + err.Error())
	}
	defer rowsExisting.Close()
	var syncptid int64
	syncptid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&syncptid)
		if err != nil {
			return errors.New("deleteSyncPoint: " + err.Error())
		}
	}
	if syncptid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("deleteSyncPoint: " + err.Error())
		}
		return errors.New("Sync point " + `"` + syncpublicid + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found sync point.")
		fmt.Println("    Deleting access grants to this sync point.")
	}
	cmd = "DELETE FROM grant WHERE syncptid = ?;"
	stmtDel, err := tx.Prepare(cmd)
	_, err = stmtDel.Exec(syncptid)
	if err != nil {
		return errors.New("deleteSyncPoint: " + err.Error())
	}
	if verbose {
		fmt.Println("    Deleting the sync point itself.")
	}
	cmd = "DELETE FROM syncpoint WHERE syncptid = ?;"
	stmtDel, err = tx.Prepare(cmd)
	_, err = stmtDel.Exec(syncptid)
	if err != nil {
		return errors.New("deleteSyncPoint: " + err.Error())
	}
	err = tx.Commit()
	if err != nil {
		return errors.New("deleteSyncPoint: " + err.Error())
	}
	if verbose {
		fmt.Println("    Sync point deleted.")
	}
	return nil
}

func deleteUser(verbose bool, db *sql.DB, auth *authinfo, email string) error {
	if verbose {
		fmt.Println("Deleting user")
		fmt.Println("    Email:", email)
	}
	if (auth.role & roleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE email = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(email)
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return errors.New("deleteUser: " + err.Error())
		}
	}
	if userid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("deleteUser: " + err.Error())
		}
		return errors.New("User " + `"` + email + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found email.")
		fmt.Println("    Deleting access grants for this user.")
	}
	cmd = "DELETE FROM grant WHERE userid = ?;"
	stmtDel, err := tx.Prepare(cmd)
	_, err = stmtDel.Exec(userid)
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	if verbose {
		fmt.Println("    Deleting the user.")
	}
	cmd = "DELETE FROM user WHERE userid = ?;"
	stmtDel, err = tx.Prepare(cmd)
	_, err = stmtDel.Exec(userid)
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	err = tx.Commit()
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	if verbose {
		fmt.Println("    User deleted.")
	}
	return nil
}

func getServerTreeForSyncPoint(verbose bool, db *sql.DB, auth *authinfo, syncpublicid string) ([]wfileInfo, error) {
	if verbose {
		fmt.Println("Retrieving files for sync point:", syncpublicid)
	}
	if (auth.role & roleSyncPointUser) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the sync point user role.")
	}
	cmd := "SELECT syncptid FROM syncpoint WHERE publicid = ?;"
	stmtSelSync, err := db.Prepare(cmd)
	if err != nil {
		return nil, errors.New("GetServerTreeForSyncPoint: " + err.Error())
	}
	rowsSync, err := stmtSelSync.Query(syncpublicid)
	if err != nil {
		return nil, errors.New("GetServerTreeForSyncPoint: " + err.Error())
	}
	defer rowsSync.Close()
	var syncptid int64
	syncptid = 0
	for rowsSync.Next() {
		err = rowsSync.Scan(&syncptid)
		if err != nil {
			return nil, errors.New("GetServerTreeForSyncPoint: " + err.Error())
		}
	}
	if syncptid == 0 {
		if verbose {
			fmt.Println("    Sync point " + `"` + syncpublicid + `"` + " not found.")
		}
		return nil, errors.New("Sync point " + `"` + syncpublicid + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Sync point found. Internal ID is:", syncptid)
	}
	cmd = "SELECT filepath, modtime, filehash, reupneeded FROM fileinfo WHERE syncptid = ? ORDER BY filepath;"
	stmtSelFileInfo, err := db.Prepare(cmd)
	if err != nil {
		return nil, errors.New("GetServerTreeForSyncPoint: " + err.Error())
	}
	rowsFileInfo, err := stmtSelFileInfo.Query(syncptid)
	if err != nil {
		return nil, errors.New("GetServerTreeForSyncPoint: " + err.Error())
	}
	defer rowsFileInfo.Close()
	var filepath string
	var modtime int64
	var filehash string
	var reupi int
	var reup bool
	result := make([]wfileInfo, 0)
	for rowsFileInfo.Next() {
		err = rowsFileInfo.Scan(&filepath, &modtime, &filehash, &reupi)
		if err != nil {
			return nil, errors.New("GetServerTreeForSyncPoint: " + err.Error())
		}
		if verbose {
			fmt.Println("    ", filepath)
		}
		if reupi == 0 {
			reup = false
		} else {
			reup = true
		}
		result = append(result, wfileInfo{filepath, 0, modtime, filehash, reup})
	}
	return result, nil
}

func sendFile(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *authinfo, syncpublicid string, filepath string, filehash string) (string, error) {
	//
	// Step 1: Find the local file and check permissions
	if verbose {
		fmt.Println("Sending: ", filepath)
	}
	if (auth.role & roleSyncPointUser) == 0 {
		wnet.Close()
		return "", errors.New("Permission denied: User is not assigned to the sync point user role.")
	}
	syncptid, localpath, err := determineAccessForSyncPoint(verbose, db, auth, syncpublicid, accessRead)
	if err != nil {
		return "", err
	}
	fileid, modtime, ourFileHash, err := getFileInfo(db, syncptid, filepath)
	if err != nil {
		return "", err
	}
	if verbose {
		fmt.Println("    Modification time:", modtime)
		fmt.Println("    File hash:", filehash)
	}
	if ourFileHash != filehash {
		return "", errors.New("SendFile: hash requested does not match server's hash of that file. File:" + `"` + filepath + `"` + ".")
	}
	localfilepath := localpath + makePathSeparatorsForThisOS(filepath)
	info, err := os.Stat(localfilepath)
	noexist := false
	if err != nil {
		if os.IsNotExist(err) {
			if verbose {
				fmt.Println("    File does not exist.")
			}
			noexist = true
		} else {
			return "", err
		}
	}
	if noexist {
		err = markFileAsReuploadneeded(db, fileid)
		if err != nil {
			return "", err
		}
		if verbose {
			fmt.Println("    File marked for reupload.")
		}
		msg := wrpc.NewDB()
		msg.StartDB("FileDoesNotExist", 0, 1)
		msg.SendDB(wnet)
		return "NoExist", nil
	}
	filesize := info.Size()
	if verbose {
		fmt.Println("    File size: ", filesize)
	}
	//
	// Step 2: Send ReceiveFile message back to client. This identical
	// to the header message sent to the server when the client uploads
	// a file. We tell them the name of the file we're going to send
	// and how big it is. The next N bytes will be the file.
	msg := wrpc.NewDB()
	msg.StartDB("ReceiveFile", 0, 1)
	msg.StartTable("", 4, 1)
	msg.AddColumn("filepath", wrpc.ColString)
	msg.AddColumn("size", wrpc.ColInt)
	msg.AddColumn("modtime", wrpc.ColInt)
	msg.AddColumn("filehash", wrpc.ColString)
	msg.StartRow()
	msg.AddRowColumnString(filepath)
	msg.AddRowColumnInt(filesize)
	msg.AddRowColumnInt(modtime)
	msg.AddRowColumnString(filehash)
	msg.SendDB(wnet)
	if verbose {
		fmt.Println("    Sent ReceiveFile message")
	}
	//
	// Step 3: Get a reply back saying "Go Ahead"
	// If we don't get the "Go Ahead And Send", we don't send the file
	rplmsg, err := wnet.NextMessage()
	if rplmsg == nil {
		return "", errors.New("Returned message is nil. Connection assumed to be closed by same client. Aborting attempt to send file.")
	}
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		return "", errors.New("Connection closed by same client.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	if verbose {
		fmt.Println("    Got reply:", reply.GetDBName())
	}
	if reply.GetDBName() != "ReceiveFileReply" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			return "", err
		}
		return "", errors.New(reply.GetDBName() + ": " + errmsg)
	}
	if verbose {
		fmt.Println("    ReceiveFile reply received")
	}
	result, err := reply.GetString(0, 0, 0)
	if err != nil {
		return "", err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return "", err
	}
	if result != "GoAheadAndSend" {
		return "", errors.New(errmsg)
	}
	if verbose {
		fmt.Println("    We got the go ahead to send.")
	}
	//
	// Step 4: Actually send the file
	// For this we send the bytes in "shove" mode, instead of using the Mini-DB RPC system
	// It's gets pushed through the crypto system, so don't worry,
	// the bits on the wire are still encrypted
	buffer := make([]byte, 32768)
	ciphertext := make([]byte, 32768) // allocated here as a memory management optimization
	fh, err := os.Open(localfilepath)
	if err != nil {
		return "", err
	}
	keepGoing := true
	for keepGoing {
		n, err := fh.Read(buffer)
		if err == nil {
			wnet.ShoveBytes(buffer[:n], ciphertext[:n])
		} else {
			if err == io.EOF {
				keepGoing = false
			} else {
				return "", err
			}
		}
	}
	fh.Close()
	if verbose {
		fmt.Println("    File bytes sent.")
	}
	//
	// Step 5: Get reply from the remote end that the bytes were
	// received and the signature checked out
	rplmsg, err = wnet.NextMessage()
	if rplmsg == nil {
		return "", errors.New("Returned message is nil. Connection assumed to be closed by same client. Aborting attempt to send file.")
	}
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		// usually err will be nil here, but we pass back err instead of nil because if it wasn't, that's what we'd do anyway
		return "", err
	}
	reply = wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	result, err = reply.GetString(0, 0, 0)
	if err != nil {
		return "", err
	}
	errmsg, err = reply.GetString(0, 0, 1)
	if err != nil {
		return "", err
	}
	if verbose {
		fmt.Println("    Received response to sending file. We are done.")
	}
	return result, nil
}

func markFileDeleted(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *authinfo, syncpublicid string, filepath string, modtime int64, filehash string) error {
	if verbose {
		fmt.Println("Marking file deleted:")
		fmt.Println("    Sync Point ID:", syncpublicid)
		fmt.Println("    File:", filepath)
		fmt.Println("    Remote hash:", filehash)
	}
	syncptid, localpath, err := determineAccessForSyncPoint(verbose, db, auth, syncpublicid, accessWrite)
	if err != nil {
		return err
	}
	fileid, modtime, ourFileHash, err := getFileInfo(db, syncptid, filepath)
	if err != nil {
		return err
	}
	if verbose {
		fmt.Println("    Modification time:", modtime)
		fmt.Println("    Local hash:", filehash)
	}
	if ourFileHash != filehash {
		return errors.New("MarkFileDeleted: hashes do not match. To protect against accidental deletions, only the most recent version of the file (as known to the server) can be deleted. Use same -u to undelete deleted files with the most recent versions. File:" + `"` + filepath + `"` + ".")
	}
	localfilepath := localpath + string(os.PathSeparator) + makePathSeparatorsForThisOS(filepath)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "UPDATE fileinfo SET modtime = ?, filehash = 'deleted', reupneeded = 0 WHERE fileid = ?;"
	stmtUpd, err := tx.Prepare(cmd)
	_, err = stmtUpd.Exec(modtime, fileid)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if verbose {
		fmt.Println("    File marked as deleted in our DB. Attempting to delete local copy of the file:", localfilepath)
	}
	err = os.Remove(localfilepath)
	if verbose {
		fmt.Println("Local file deleted. Deletion complete")
	}
	return nil
}

// Returns: new generated password. (Remember, users are not allowed to choose their own passwords.)
func resetUserPassword(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *authinfo, email string) (string, error) {
	fmt.Println("Resetting user password for:", email)
	cmd := "SELECT userid FROM user WHERE (email = ?);"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return "", err
	}
	rows, err := stmtSel.Query(email)
	if err != nil {
		return "", err
	}
	var userid int64
	userid = 0
	for rows.Next() {
		err = rows.Scan(&userid)
		if err != nil {
			return "", err
		}
	}
	if auth.userid == 0 {
		return "", errors.New("ResetUserPassword: User " + `"` + email + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    User ID is:", userid)
	}
	if auth.userid == 0 {
		return "", errors.New("ResetUserPassword: Not logged in.")
	}
	if (auth.userid & roleAdmin) == 0 {
		// not admin -- is user resetting their own password?
		if auth.userid != userid {
			return "", errors.New("ResetUserPassword: Permission denied.")
		}
	}
	// Ok, if we got here, we are going to proceed with the password reset
	password, err := generatePassword()
	if err != nil {
		return "", errors.New("ResetUserPassword: " + err.Error())
	}
	pwSaltBin, err := generatePwSalt()
	if err != nil {
		return "", errors.New("ResetUserPassword: " + err.Error())
	}
	pwsalt := hex.EncodeToString(pwSaltBin)
	pwHashBin := calculatePwHash(pwSaltBin, password)
	pwhash := hex.EncodeToString(pwHashBin)
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	cmd = "UPDATE user SET pwsalt = ?, pwhash = ? WHERE userid = ?;"
	stmtUpd, err := tx.Prepare(cmd)
	_, err = stmtUpd.Exec(pwsalt, pwhash, userid)
	if err != nil {
		return "", err
	}
	err = tx.Commit()
	if verbose {
		fmt.Println("    Password reset to:", password)
	}
	return password, err
}

// ----------------------------------------------------------------
// End of functions callable remotely
// ----------------------------------------------------------------

// ----------------------------------------------------------------
// unmarshallers
// ----------------------------------------------------------------

func unmGetTime(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection) error {
	if version != 0 {
		return errors.New("GetTime: Wrong version number")
	}
	result := getTime()
	wrpc.SendReplyScalarInt("GetTime", version, result, "", wnet)
	return nil
}

func unmReceiveFile(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		fmt.Println("ReceiveFile: Wrong version number")
	}
	syncpublicid, err := rpc.GetString(0, 0, 0)
	if err != nil {
		fmt.Println("unmReceiveFile: syncpublicid:", err)
		return err
	}
	filepath, err := rpc.GetString(0, 0, 1)
	if err != nil {
		fmt.Println("unmReceiveFile: filepath:", err)
		return err
	}
	size, err := rpc.GetInt(0, 0, 2)
	if err != nil {
		fmt.Println("unmReceiveFile: size:", err)
		return err
	}
	modtime, err := rpc.GetInt(0, 0, 3)
	if err != nil {
		fmt.Println("unmReceiveFile: modtime:", err)
		return err
	}
	filehash, err := rpc.GetString(0, 0, 4)
	if err != nil {
		fmt.Println("unmReceiveFile: filehash:", err)
		return err
	}
	result, err := receiveFile(verbose, db, wnet, auth, syncpublicid, filepath, size, modtime, filehash)
	wrpc.SendReplyScalarString("ReceiveFile", version, result, errorToString(err), wnet)
	return nil
}

func unmLogin(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("Login: Version number mismatch.")
	}
	email, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	password, err := rpc.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	err = login(db, auth, verbose, email, password)
	wrpc.SendReplyVoid("Login", version, errorToString(err), wnet)
	return nil
}

func unmListUsers(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("ListUsers: Version number mismatch.")
	}
	userlist, err := listUsers(db, auth)
	reply := wrpc.NewDB()
	reply.StartDB("ListUsersReply", 0, 2)
	reply.StartTable("userlist", 2, len(userlist))
	reply.AddColumn("", wrpc.ColString)
	reply.AddColumn("", wrpc.ColInt)
	for ii := 0; ii < len(userlist); ii++ {
		reply.StartRow()
		reply.AddRowColumnString(userlist[ii].email)
		reply.AddRowColumnInt(int64(userlist[ii].role))
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmAddUser(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("AddUser: Version number mismatch.")
	}
	email, err := rpc.GetString(0, 0, 0)
	if err != nil {
		fmt.Println("unmAdduser: email:", err)
		return err
	}
	role64, err := rpc.GetInt(0, 0, 1)
	if err != nil {
		fmt.Println("unmAdduser: role:", err)
		return err
	}
	role := int(role64)
	password, err := addUser(verbose, db, auth, email, role)
	reply := wrpc.NewDB()
	reply.StartDB("AddUserReply", 0, 1)
	reply.StartTable("", 2, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(password)
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmAddSyncPoint(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("AddSyncPoint: Version number mismatch.")
	}
	path, err := rpc.GetString(0, 0, 0)
	publicid, err := addSyncPoint(verbose, db, auth, path)
	reply := wrpc.NewDB()
	reply.StartDB("AddSyncPointReply", 0, 1)
	reply.StartTable("", 2, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(publicid)
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmListSyncPoints(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("ListSyncPoints: Version number mismatch.")
	}
	syncpointlist, err := listSyncPoints(db, auth)
	reply := wrpc.NewDB()
	reply.StartDB("ListSyncPointsReply", 0, 2)
	reply.StartTable("syncpointlist", 2, len(syncpointlist))
	reply.AddColumn("", wrpc.ColString)
	reply.AddColumn("", wrpc.ColString)
	for ii := 0; ii < len(syncpointlist); ii++ {
		reply.StartRow()
		reply.AddRowColumnString(syncpointlist[ii].publicid)
		reply.AddRowColumnString(syncpointlist[ii].path)
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmAddGrant(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("AddGrant: Version number mismatch.")
	}
	email, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	syncpublicid, err := rpc.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	access64, err := rpc.GetInt(0, 0, 2)
	if err != nil {
		return err
	}
	access := int(access64)
	err = addGrant(verbose, db, auth, email, syncpublicid, access)
	return wrpc.SendReplyVoid("AddGrant", version, errorToString(err), wnet)
}

func unmListGrants(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("ListGrants: Version number mismatch.")
	}
	grantlist, err := listGrants(db, auth)
	reply := wrpc.NewDB()
	reply.StartDB("ListGrantsReply", 0, 2)
	reply.StartTable("grantlist", 3, len(grantlist))
	reply.AddColumn("", wrpc.ColString)
	reply.AddColumn("", wrpc.ColString)
	reply.AddColumn("", wrpc.ColInt)
	for ii := 0; ii < len(grantlist); ii++ {
		reply.StartRow()
		reply.AddRowColumnString(grantlist[ii].email)
		reply.AddRowColumnString(grantlist[ii].publicid)
		reply.AddRowColumnInt(int64(grantlist[ii].access))
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmDeleteGrant(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("DeleteGrant: Version number mismatch.")
	}
	email, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	syncpublicid, err := rpc.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	err = deleteGrant(verbose, db, auth, email, syncpublicid)
	return wrpc.SendReplyVoid("DeleteGrant", version, errorToString(err), wnet)
}

func unmDeleteSyncPoint(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("DeleteSyncPoint: Version number mismatch.")
	}
	syncpublicid, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	err = deleteSyncPoint(verbose, db, auth, syncpublicid)
	return wrpc.SendReplyVoid("DeleteSyncPoint", version, errorToString(err), wnet)
}

func unmDeleteUser(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("DeleteUser: Version number mismatch.")
	}
	email, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	err = deleteUser(verbose, db, auth, email)
	return wrpc.SendReplyVoid("DeleteUser", version, errorToString(err), wnet)
}

func unmGetServerTreeForSyncPoint(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("GetServerTreeForSyncPoint: Version number mismatch.")
	}
	syncpublicid, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	filelist, err := getServerTreeForSyncPoint(verbose, db, auth, syncpublicid)
	reply := wrpc.NewDB()
	reply.StartDB("GetServerTreeForSyncPointReply", 0, 2)
	reply.StartTable("filelist", 4, len(filelist))
	reply.AddColumn("filepath", wrpc.ColString)
	reply.AddColumn("filetime", wrpc.ColInt)
	reply.AddColumn("filehash", wrpc.ColString)
	reply.AddColumn("reupneeded", wrpc.ColBool)
	for ii := 0; ii < len(filelist); ii++ {
		reply.StartRow()
		reply.AddRowColumnString(filelist[ii].filePath)
		reply.AddRowColumnInt(int64(filelist[ii].fileTime))
		reply.AddRowColumnString(filelist[ii].fileHash)
		reply.AddRowColumnBool(filelist[ii].reupNeeded)
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("success", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmSendFile(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("SendFile: Version number mismatch.")
	}
	syncpublicid, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	filepath, err := rpc.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	filehash, err := rpc.GetString(0, 0, 2)
	if err != nil {
		return err
	}
	result, err := sendFile(verbose, db, wnet, auth, syncpublicid, filepath, filehash)
	if result != "ReceptionComplete" {
		return err
	}
	return nil
}

func unmMarkFileDeleted(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("MarkFileDeleted: Version number mismatch.")
	}
	syncpublicid, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	filepath, err := rpc.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	modtime, err := rpc.GetInt(0, 0, 2)
	if err != nil {
		return err
	}
	filehash, err := rpc.GetString(0, 0, 3)
	if err != nil {
		return err
	}
	err = markFileDeleted(verbose, db, wnet, auth, syncpublicid, filepath, modtime, filehash)
	return wrpc.SendReplyVoid("MarkFileDeleted", version, errorToString(err), wnet)
}

func unmResetUserPassword(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if version != 0 {
		return errors.New("ResetUserPassword: Version number mismatch.")
	}
	email, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	password, err := resetUserPassword(verbose, db, wnet, auth, email)
	return wrpc.SendReplyScalarString("ResetUserPassword", version, password, errorToString(err), wnet)
}

// ----------------------------------------------------------------
// end of unmarshallers
// ----------------------------------------------------------------

func sendDispatchErrorReply(wnet wrpc.IWNetConnection, errmsg string) error {
	var reply wrpc.XWRPC
	reply.StartDB("DispatchError", 0, 1)
	reply.StartTable("", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errmsg)
	return reply.SendDB(wnet)
}

func dispatch(fcname string, version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *authinfo, verbose bool) error {
	if verbose {
		fmt.Println("Dispatching to function:", fcname)
	}
	switch fcname {
	case "GetTime":
		return unmGetTime(version, rpc, wnet)
	case "Login":
		return unmLogin(version, rpc, wnet, db, auth, verbose)
	case "ListUsers":
		return unmListUsers(version, rpc, wnet, db, auth, verbose)
	case "AddUser":
		return unmAddUser(version, rpc, wnet, db, auth, verbose)
	case "AddSyncPoint":
		return unmAddSyncPoint(version, rpc, wnet, db, auth, verbose)
	case "ListSyncPoints":
		return unmListSyncPoints(version, rpc, wnet, db, auth, verbose)
	case "AddGrant":
		return unmAddGrant(version, rpc, wnet, db, auth, verbose)
	case "ListGrants":
		return unmListGrants(version, rpc, wnet, db, auth, verbose)
	case "DeleteGrant":
		return unmDeleteGrant(version, rpc, wnet, db, auth, verbose)
	case "DeleteSyncPoint":
		return unmDeleteSyncPoint(version, rpc, wnet, db, auth, verbose)
	case "DeleteUser":
		return unmDeleteUser(version, rpc, wnet, db, auth, verbose)
	case "GetServerTreeForSyncPoint":
		return unmGetServerTreeForSyncPoint(version, rpc, wnet, db, auth, verbose)
	case "ReceiveFile":
		return unmReceiveFile(version, rpc, wnet, db, auth, verbose)
	case "SendFile":
		return unmSendFile(version, rpc, wnet, db, auth, verbose)
	case "MarkFileDeleted":
		return unmMarkFileDeleted(version, rpc, wnet, db, auth, verbose)
	case "ResetUserPassword":
		return unmResetUserPassword(version, rpc, wnet, db, auth, verbose)
	default:
		if verbose {
			fmt.Println("Dispatch: ", fcname, "not found.")
		}
		fmt.Println("Function name is:", fcname)
		return errors.New("Dispatch failed: function " + `"` + fcname + `"` + " not found.")
	}
}

func handleConnection(conn net.Conn, verose bool, db *sql.DB, symkey []byte, hmackey []byte, verbose bool) {
	var auth authinfo
	auth.userid = 0
	auth.role = 0
	wnet := wrpc.NewConnection()
	wnet.SetKeys(symkey, hmackey)
	for {
		message, err := wnet.DevelopConnectionMessage(conn)
		if err != nil {
			if err.Error()[:11] == "No message." {
				if verbose {
					fmt.Println("No more messages. Connection closed as part of normal operation.")
				}
				return
			}
			fmt.Println("Error occurred in message development:", err)
			return
		} else {
			if message == nil {
				fmt.Println("Nil message was returned from wnet.DevelopConnectionMessage()")
				return
			} else {
				rpc := wrpc.NewDB()
				rpc.ReceiveDB(message)
				fcname := rpc.GetDBName()
				version := rpc.GetDBVersion()
				err = dispatch(fcname, version, rpc, wnet, db, &auth, verbose)
				if err != nil {
					fmt.Println("Error occurred in dispatch to", fcname, ":", err)
					err = sendDispatchErrorReply(wnet, err.Error())
					if err != nil {
						fmt.Println("Could not send dispatch error reply:", err)
					}
				}
			}
		}
	}
}

func trim(stg string) string {
	return strings.Trim(stg, " \t\n\r")
}

func getLine(reader *bufio.Reader) (string, error) {
	result, err := reader.ReadString('\n')
	return trim(result), err
}

func main() {
	vflag := flag.Bool("v", false, "verbose mode")
	gflag := flag.Bool("g", false, "generate key")
	kflag := flag.Bool("k", false, "show existing key")
	iflag := flag.Bool("i", false, "initialize")
	pflag := flag.Bool("p", false, "configure port number")
	aflag := flag.Bool("a", false, "create admin account")
	flag.Parse()
	verbose := *vflag
	configurePort := *pflag
	generateKeys := *gflag
	initialize := *iflag
	showKeys := *kflag
	createAdmin := *aflag
	if verbose {
		fmt.Println("samed version 0.0")
		fmt.Println("Flags:")
		fmt.Println("    Generate key mode:", onOff(generateKeys))
		fmt.Println("    Initialize:", onOff(initialize))
		fmt.Println("    Show keys:", onOff(showKeys))
		fmt.Println("    Create admin:", onOff(createAdmin))
	}
	if initialize {
		db, err := sql.Open("sqlite3", databaseFileName)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = initializeSettings(db)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = initializeServerTables(db)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Initialized.")
		return
	}
	db, err := sql.Open("sqlite3", databaseFileName)
	defer db.Close()
	if generateKeys {
		symkey, err := generateAESKey()
		if err != nil {
			fmt.Println(err)
			return
		}
		hmackey, err := generateSHAKey()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(hex.EncodeToString(symkey))
		fmt.Println(hex.EncodeToString(hmackey))
		setNameValuePair(db, "symmetrickey", hex.EncodeToString(symkey), verbose, false)
		setNameValuePair(db, "hmackey", hex.EncodeToString(hmackey), verbose, false)
		return
	}
	if createAdmin {
		err := createTheAdminAccount(db, verbose)
		if err != nil {
			fmt.Println(err)
			return
		}
		return
	}
	if configurePort {
		portnum := 0
		for portnum == 0 {
			fmt.Print("Port: ")
			// fmt.Scanln(&ptStr)
			keyboard := bufio.NewReader(os.Stdin)
			ptStr, err := getLine(keyboard)
			if err != nil {
				fmt.Println(err)
				return
			}
			portnum = strToInt(ptStr)
		}
		setNameValuePair(db, "port", intToStr(portnum), verbose, false)
		if verbose {
			fmt.Println("Port number set to", portnum)
		}
		return
	}
	ptNum, err := getValue(db, "port", "", verbose)
	if err != nil {
		fmt.Println(err)
		return
	}
	portnum := strToInt(ptNum)
	if portnum == 0 {
		fmt.Println("Port number has not been set.")
		fmt.Println("Use samed -p to configure the port number")
		return
	}

	symKeyStr, err := getValue(db, "symmetrickey", "", verbose)
	if err != nil {
		fmt.Println(err)
		return
	}

	hmacKeyStr, err := getValue(db, "hmackey", "", verbose)
	if err != nil {
		fmt.Println(err)
		return
	}
	symkey, err := hex.DecodeString(symKeyStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	hmackey, err := hex.DecodeString(hmacKeyStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	if showKeys {
		fmt.Println(hex.EncodeToString(symkey))
		fmt.Println(hex.EncodeToString(hmackey))
		return
	}
	if (len(symkey) == 0) || (len(hmackey) == 0) {
		fmt.Println("Key has not been set up.")
		fmt.Println("Use samed -g to generate key.")
		fmt.Println("Use samed -k to export key for clients.")
		return
	}

	// if we got here, we're going to listen for incoming connections!

	listener, err := net.Listen("tcp", ":"+intToStr(portnum))
	if err != nil {
		fmt.Println(err)
		return
	}
	if verbose {
		fmt.Println("samed listening on port " + intToStr(portnum))
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error occurred when trying to accept a connection:", err)
		} else {
			if verbose {
				fmt.Println("samed responding to incoming connection.")
			}
			go handleConnection(conn, verbose, db, symkey, hmackey, verbose)
		}
	}
}
