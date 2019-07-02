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
	"samecommon"
	"strconv"
	"strings"
	"time"
	"wrpc"
)

const databaseFileName = "sameserver.db"

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

func generatePwSalt() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func generateSyncPointId() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func generateChallenge() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
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
	cmd = "CREATE TABLE user (userid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, pwsalt TEXT NOT NULL, pwhash TEXT NOT NULL, challengeresponsekey TEXT NOT NULL, role INTEGER);"
	stmtCreate, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	_, err = stmtCreate.Exec()
	if err != nil {
		return err
	}
	cmd = "CREATE INDEX idx_us_em ON user (username);"
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
	cmd = "CREATE TABLE fileinfo (fileid INTEGER PRIMARY KEY AUTOINCREMENT, syncptid INTEGER NOT NULL, filepath TEXT NOT NULL, modtime INTEGER NOT NULL, filehash TEXT NOT NULL, reupneeded INTEGER NOT NULL, localstorage TEXT NOT NULL);"
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

func generateUserPasswordSet() ([]byte, []byte, string, string, string, error) {
	passwordStore, err := samecommon.GenerateSHAKey()
	if err != nil {
		return nil, nil, "", "", "", err
	}
	// "password" CR is the challenge-response shared secret
	passwordCR, err := samecommon.GenerateSHAKey()
	if err != nil {
		return nil, nil, "", "", "", err
	}
	pwSaltBin, err := generatePwSalt()
	if err != nil {
		return nil, nil, "", "", "", err
	}
	pwsalt := hex.EncodeToString(pwSaltBin)
	pwHashBin := samecommon.CalculatePwHash(pwSaltBin, passwordStore)
	pwhash := hex.EncodeToString(pwHashBin)
	challengeresponsekey := hex.EncodeToString(passwordCR)
	return passwordStore, passwordCR, pwsalt, pwhash, challengeresponsekey, nil
}

func passwordPiecesToPassword(passwordStore []byte, passwordCR []byte) []byte {
	combo := make([]byte, 64)
	copy(combo[:32], passwordStore)
	copy(combo[32:], passwordCR)
	return combo
}

func createBuiltInAccount(verbose bool, db *sql.DB, username string, role int) (string, error) {
	if verbose {
		fmt.Println("Creating built-in account called:", username)
	}
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	cmd := "SELECT userid FROM user WHERE username = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return "", err
	}
	rowsExisting, err := stmtSelExisting.Query(username)
	if err != nil {
		return "", err
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return "", err
		}
	}
	passwordStore, passwordCR, pwsalt, pwhash, challengeresponsekey, err := generateUserPasswordSet()
	if err != nil {
		err2 := tx.Rollback()
		if err2 != nil {
			return "", err2
		} else {
			return "", err
		}
	}
	if userid == 0 {
		cmd = "INSERT INTO user (username, pwsalt, pwhash, challengeresponsekey, role) VALUES (?, ?, ?, ?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return "", err
		}
		_, err = stmtIns.Exec(username, pwsalt, pwhash, challengeresponsekey, role)
		if err != nil {
			return "", err
		}
		if verbose {
			fmt.Println("    Built-in account created.")
		}
	} else {
		cmd = "UPDATE user SET username = ?, pwsalt = ?, pwhash = ?, challengeresponsekey = ?, role = ? WHERE userid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(username, pwsalt, pwhash, challengeresponsekey, role, userid)
		if err != nil {
			return "", err
		}
		if verbose {
			fmt.Println("    Built-in account ", `"`+username+`"`, "already exists.")
			fmt.Println("    Account reset.")
		}
	}
	err = tx.Commit()
	password := passwordPiecesToPassword(passwordStore, passwordCR)
	if verbose {
		fmt.Println("    Account created:")
		fmt.Println("        username (username): ", username)
		fmt.Println("        password: ", password)
		fmt.Println("        password salt: ", pwsalt)
		fmt.Println("        password hash: ", pwhash)
		fmt.Println("        role: ", samecommon.RoleFlagsToString(role))
	}
	passwEncodeBin := make([]byte, 86)
	num := ascii85.Encode(passwEncodeBin, password)
	asciiPassword := string(passwEncodeBin[:num])
	if username == "admin" {
		fmt.Println("Admin password is:", asciiPassword)
	}
	return asciiPassword, err
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

func determineAccessForSyncPoint(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, syncpublicid string, accessRequested int) (int64, string, error) {
	if verbose {
		fmt.Println("Checking access for: userid", auth.UserId, "sync point public ID", syncpublicid, "with requested access flags", samecommon.AccessFlagsToString(accessRequested))
	}
	if auth.UserId == 0 {
		return 0, "", errors.New("Access denied: not logged in.")
	}
	if (auth.Role & samecommon.RoleSyncPointUser) == 0 {
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
	rowsGrant, err := stmtSelGrant.Query(syncptid, auth.UserId)
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
	return syncptid, path, errors.New("Access denied. No access grant for requested access:" + samecommon.AccessFlagsToString(accessRequested))
}

func stashFileInfo(verbose bool, db *sql.DB, syncptid int64, filepath string, modtime int64, filehash string, localstorage string) error {
	if verbose {
		fmt.Println("For file", filepath, "stashing hash", filehash, "modtime", modtime, "in local storage", localstorage)
	}
	filepath = samecommon.MakePathSeparatorsStandard(filepath)
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
		cmd = "INSERT INTO fileinfo (syncptid, filepath, modtime, filehash, reupneeded, localstorage) VALUES (?, ?, ?, ?, 0, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return err
		}
		_, err = stmtIns.Exec(syncptid, filepath, modtime, filehash, localstorage)
		if err != nil {
			return err
		}
	} else {
		cmd = "UPDATE fileinfo SET modtime = ?, filehash = ?, reupneeded = 0, localstorage = ? WHERE fileid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(modtime, filehash, localstorage, fileid)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

func getFileInfo(db *sql.DB, syncptid int64, filepath string) (int64, int64, string, string, error) {
	filepath = samecommon.MakePathSeparatorsStandard(filepath)
	cmd := "SELECT fileid, modtime, filehash, localstorage FROM fileinfo WHERE (syncptid = ?) AND (filepath = ?);"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return 0, 0, "", "", err
	}
	rows, err := stmtSel.Query(syncptid, filepath)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer rows.Close()
	var fileid int64
	fileid = 0
	var modtime int64
	var filehash string
	var localstorage string
	for rows.Next() {
		err = rows.Scan(&fileid, &modtime, &filehash, &localstorage)
		if err != nil {
			return 0, 0, "", "", err
		}
	}
	if fileid == 0 {
		return 0, 0, "", "", errors.New("Could not find file: " + `"` + filepath + `"`)
	}
	return fileid, modtime, filehash, localstorage, nil
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

func calculateFilenameHash(filenameordirectory string) []byte {
	sum := sha256.Sum256([]byte(filenameordirectory))
	result := make([]byte, 32)
	// copy(result,sum) -- gives error second argument to copy should be slice or string; have [32]byte
	for ii := 0; ii < 32; ii++ {
		result[ii] = sum[ii]
	}
	return result
}

func convertFilePathToLocalStoragePath(filepath string) string {
	pieces := strings.Split(filepath, "/")
	lnp := len(pieces)
	result := ""
	for ii := 1; ii < lnp; ii++ {
		result += "/" + hex.EncodeToString(calculateFilenameHash(pieces[ii]))
	}
	return result
}

func generateTemporaryFileName() (string, error) {
	rndbts := make([]byte, 16)
	_, err := rand.Read(rndbts)
	return "temp_temp_" + hex.EncodeToString(rndbts), err
}

// ----------------------------------------------------------------
// functions callable remotely
// ----------------------------------------------------------------

func getTime() int64 {
	now := time.Now()
	result := now.UnixNano()
	return result
}

func receiveFile(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *samecommon.AuthInfo, syncpublicid string, filepath string, size int64, modtime int64, filehash string) (string, error) {
	version := 0
	if verbose {
		fmt.Println("Receiving file:", filepath)
	}
	//
	// Step 1: Check permissions
	if (auth.Role & samecommon.RoleSyncPointUser) == 0 {
		wnet.Close()
		return "", errors.New("Permission denied: User is not assigned to the sync point user role.")
	}
	syncptid, localpath, err := determineAccessForSyncPoint(verbose, db, auth, syncpublicid, samecommon.AccessWrite)
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
	tempFileName, err := generateTemporaryFileName()
	if err != nil {
		return "", errors.New("receiveFile: generateTemporaryFileName: " + err.Error())
	}
	var fhOut *os.File
	fhOut, err = os.Create(localpath + string(os.PathSeparator) + tempFileName)
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
	localstorage := convertFilePathToLocalStoragePath(filepath)
	if verbose {
		fmt.Println("    Local storage:", localstorage)
	}
	err = os.Rename(localpath+string(os.PathSeparator)+tempFileName, localpath+samecommon.MakePathSeparatorsForThisOS(localstorage))
	if err != nil {
		mkerr := samecommon.MakePathForFile(localpath + samecommon.MakePathSeparatorsForThisOS(localstorage))
		if mkerr != nil {
			return "", errors.New("receiveFile: make path: " + err.Error())
		}
		mverr := os.Rename(localpath+string(os.PathSeparator)+tempFileName, localpath+samecommon.MakePathSeparatorsForThisOS(localstorage))
		if mverr != nil {
			return "", errors.New("receiveFile: rename: " + err.Error())
		}
	}
	//
	// Step 5: Stash all the info about the file in our server database
	err = stashFileInfo(verbose, db, syncptid, filepath, modtime, filehash, localstorage)
	if err != nil {
		return "", errors.New("receiveFile: stash file info: " + err.Error())
	}
	//
	// Step 6: Return "Reception complete" message which will be sent back to the client as the reply
	return "ReceptionComplete", nil
}

func login(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *samecommon.AuthInfo, username string, password []byte) error {
	cmd := "SELECT userid, pwsalt, pwhash, challengeresponsekey, role FROM user WHERE username = ?;"
	stmtSelExisting, err := db.Prepare(cmd)
	if err != nil {
		return errors.New("login 622: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(username)
	if err != nil {
		return errors.New("login 626: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	var pwSaltTxt string
	var pwHashTxt string
	var challengeresponsekey string
	var role int
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid, &pwSaltTxt, &pwHashTxt, &challengeresponsekey, &role)
		if err != nil {
			return errors.New("login 638: " + err.Error())
		}
	}
	if userid == 0 {
		return errors.New("Username (email) " + `"` + username + `"` + " not found.")
	}
	pwSaltBin, err := hex.DecodeString(pwSaltTxt)
	if err != nil {
		return errors.New("login 647: " + err.Error())
	}
	pwHashBin1 := samecommon.CalculatePwHash(pwSaltBin, password)
	pwHashBin2, err := hex.DecodeString(pwHashTxt)
	if err != nil {
		return errors.New("login 652: " + err.Error())
	}
	if subtle.ConstantTimeCompare(pwHashBin1, pwHashBin2) == 0 {
		if verbose {
			fmt.Println("    Incorrect password.")
		}
		return errors.New("Incorrect password.")
	}
	pwCRSecretBin, err := hex.DecodeString(challengeresponsekey)
	if err != nil {
		return errors.New("login 662: " + err.Error())
	}
	challengeBin, err := generateChallenge()
	if err != nil {
		return errors.New("login 666: " + err.Error())
	}
	// We've verified the user exists. Now we send our challenge.
	msg := wrpc.NewDB()
	msg.StartDB("Challenge", 0, 1)
	msg.StartTable("", 2, 1)
	msg.AddColumn("", wrpc.ColByteArray)
	msg.StartRow()
	msg.AddRowColumnByteArray(challengeBin)
	msg.SendDB(wnet)
	if verbose {
		challengeTxt := hex.EncodeToString(challengeBin)
		fmt.Println("    Challenge:", challengeTxt)
		fmt.Println("    Sent Challenge message")
	}
	//
	rplmsg, err := wnet.NextMessage()
	if rplmsg == nil {
		return errors.New("Returned message is nil. Connection assumed to be closed by same client. Aborting challenge/response attempt.")
	}
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		return errors.New("Connection closed by same client.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	if verbose {
		fmt.Println("    Got reply:", reply.GetDBName())
	}
	if reply.GetDBName() != "Response" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			return err
		}
		return errors.New(reply.GetDBName() + ": " + errmsg)
	}
	responseBin, err := reply.GetByteArray(0, 0, 0)
	if err != nil {
		return err
	}
	if verbose {
		fmt.Println("    Response received")
		responseTxt := hex.EncodeToString(responseBin)
		fmt.Println("    Response:", responseTxt)
	}
	// We do the same calculation ourselves to see what the respose should be
	combo := append(pwCRSecretBin, challengeBin...) // destroys pwCRSecretBin, good thing we don't use it for anything else in this function
	sum := sha256.Sum256(combo)
	shouldBeBin := make([]byte, 32)
	// copy(shouldBeBin,sum) -- gives error second argument to copy should be slice or string; have [32]byte
	for ii := 0; ii < 32; ii++ {
		shouldBeBin[ii] = sum[ii]
	}
	if verbose {
		shouldBeTxt := hex.EncodeToString(shouldBeBin)
		fmt.Println("    Response should be:", shouldBeTxt)
	}
	if subtle.ConstantTimeCompare(responseBin, shouldBeBin) == 0 {
		if verbose {
			fmt.Println("    Incorrect challenge/response.")
		}
		return errors.New("Incorrect challenge/response.")
	}
	auth.UserId = userid
	auth.Role = role
	if verbose {
		fmt.Println("    Logged in as username", username, "userid", userid, "role flags:", samecommon.RoleFlagsToString(role))
	}
	return nil
}

func listUsers(db *sql.DB, auth *samecommon.AuthInfo) ([]samecommon.ListUserInfo, error) {
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	result := make([]samecommon.ListUserInfo, 0)
	cmd := "SELECT username, role FROM user WHERE 1 ORDER BY username;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return result, errors.New("listUsers: " + err.Error())
	}
	rows, err := stmtSel.Query()
	if err != nil {
		return result, errors.New("listUsers: " + err.Error())
	}
	var username string
	var role int
	for rows.Next() {
		err = rows.Scan(&username, &role)
		if err != nil {
			return result, errors.New("listUsers: " + err.Error())
		}
		result = append(result, samecommon.ListUserInfo{username, role})
	}
	return result, nil
}

func addUser(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, username string, role int) ([]byte, error) {
	if verbose {
		fmt.Println("Attempting to add User " + username + " with role: " + samecommon.RoleFlagsToString(role))
	}
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, errors.New("addUser: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE username = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return nil, errors.New("addUser: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(username)
	if err != nil {
		return nil, errors.New("addUser: " + err.Error())
	}
	defer rowsExisting.Close()
	var userid int64
	userid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&userid)
		if err != nil {
			return nil, errors.New("addUser: " + err.Error())
		}
	}
	passwordStore, passwordCR, pwsalt, pwhash, challengeresponsekey, err := generateUserPasswordSet()
	if userid == 0 {
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return nil, errors.New("addUser: " + err2.Error())
			} else {
				return nil, errors.New("addUser: " + err.Error())
			}
		}
		cmd = "INSERT INTO user (username, pwsalt, pwhash, challengeresponsekey, role) VALUES (?, ?, ?, ?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return nil, errors.New("addUser: " + err2.Error())
			} else {
				return nil, errors.New("addUser: " + err.Error())
			}
		}
		_, err = stmtIns.Exec(username, pwsalt, pwhash, challengeresponsekey, role)
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return nil, errors.New("addUser: " + err2.Error())
			} else {
				return nil, errors.New("addUser: " + err.Error())
			}
		}
		if verbose {
			fmt.Println("    User does not exist, will be added")
		}
	} else {
		err := tx.Rollback()
		if err != nil {
			return nil, errors.New("addUser: " + err.Error())
		}
		if verbose {
			fmt.Println("    User already exists")
		}
		return nil, errors.New("addUser: User already exists.")
	}
	err = tx.Commit()
	if err != nil {
		return nil, errors.New("addUser: " + err.Error())
	}
	if verbose {
		fmt.Println("    User " + username + " added with role:" + samecommon.RoleFlagsToString(role))
	}
	password := passwordPiecesToPassword(passwordStore, passwordCR)
	return password, nil
}

func addSyncPoint(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, path string) (string, error) {
	if verbose {
		fmt.Println("Adding sync point with path", path)
	}
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return "", errors.New("Permission denied: User is not assigned to the admin role.")
	}
	if len(path) == 0 {
		return "", errors.New("No path specified.")
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

func listSyncPoints(db *sql.DB, auth *samecommon.AuthInfo) ([]samecommon.ListSyncPointInfo, error) {
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	result := make([]samecommon.ListSyncPointInfo, 0)
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
		result = append(result, samecommon.ListSyncPointInfo{publicid, path})
	}
	return result, nil
}

func addGrant(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, username string, syncpublicid string, access int) error {
	if verbose {
		fmt.Println("Granting access to sync point for user.")
		fmt.Println("    Username (email):", username)
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE username = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("addGrant: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(username)
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
		return errors.New("Username (email) " + `"` + username + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found username.")
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

func listGrants(db *sql.DB, auth *samecommon.AuthInfo) ([]samecommon.ListGrantInfo, error) {
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return nil, errors.New("Permission denied: User is not assigned to the admin role.")
	}
	result := make([]samecommon.ListGrantInfo, 0)
	cmd := "SELECT user.username, syncpoint.publicid, grant.access FROM user, grant, syncpoint WHERE (user.userid = grant.userid) AND (grant.syncptid = syncpoint.syncptid) ORDER BY user.username;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return result, errors.New("listGrants: " + err.Error())
	}
	rows, err := stmtSel.Query()
	if err != nil {
		return result, errors.New("listGrants: " + err.Error())
	}
	var username string
	var publicid string
	var access int
	for rows.Next() {
		err = rows.Scan(&username, &publicid, &access)
		if err != nil {
			return result, errors.New("listGrants: " + err.Error())
		}
		result = append(result, samecommon.ListGrantInfo{username, publicid, access})
	}
	return result, nil
}

func deleteGrant(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, username string, syncpublicid string) error {
	if verbose {
		fmt.Println("Revoking access to sync point for user.")
		fmt.Println("    Username (email):", username)
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE username = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteGrant: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(username)
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
		return errors.New("Username (email) " + `"` + username + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found username.")
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
		return errors.New("User " + `"` + username + `"` + " does not have access to " + `"` + syncpublicid + `"` + ".")
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

func deleteSyncPoint(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, syncpublicid string) error {
	if verbose {
		fmt.Println("Deleting sync point")
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	if (auth.Role & samecommon.RoleAdmin) == 0 {
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

func deleteUser(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, username string) error {
	if verbose {
		fmt.Println("Deleting user")
		fmt.Println("    Username (email):", username)
	}
	if (auth.Role & samecommon.RoleAdmin) == 0 {
		return errors.New("Permission denied: User is not assigned to the admin role.")
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	cmd := "SELECT userid FROM user WHERE username = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return errors.New("deleteUser: " + err.Error())
	}
	rowsExisting, err := stmtSelExisting.Query(username)
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
		return errors.New("User " + `"` + username + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found username.")
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

func getServerTreeForSyncPoint(verbose bool, db *sql.DB, auth *samecommon.AuthInfo, syncpublicid string) ([]samecommon.SameFileInfo, error) {
	if verbose {
		fmt.Println("Retrieving files for sync point:", syncpublicid)
	}
	if (auth.Role & samecommon.RoleSyncPointUser) == 0 {
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
	result := make([]samecommon.SameFileInfo, 0)
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
		result = append(result, samecommon.SameFileInfo{filepath, 0, modtime, filehash, reup})
	}
	return result, nil
}

func sendFile(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *samecommon.AuthInfo, syncpublicid string, filepath string, filehash string) (string, error) {
	//
	// Step 1: Find the local file and check permissions
	if verbose {
		fmt.Println("Sending: ", filepath)
	}
	if (auth.Role & samecommon.RoleSyncPointUser) == 0 {
		wnet.Close()
		return "", errors.New("Permission denied: User is not assigned to the sync point user role.")
	}
	syncptid, localpath, err := determineAccessForSyncPoint(verbose, db, auth, syncpublicid, samecommon.AccessRead)
	if err != nil {
		return "", err
	}
	fileid, modtime, ourFileHash, ourLocalStorage, err := getFileInfo(db, syncptid, filepath)
	if err != nil {
		return "", err
	}
	if verbose {
		fmt.Println("    Modification time:", modtime)
		fmt.Println("    File hash:", filehash)
		fmt.Println("    Local storage:", ourLocalStorage)
	}
	if ourFileHash != filehash {
		if verbose {
			fmt.Println("    Error: file hash mismatch")
			fmt.Println("    Requested file hash:", filehash)
			fmt.Println("    Our file hash:", ourFileHash)
		}
		return "", errors.New("SendFile: hash requested does not match server's hash of that file. File:" + `"` + filepath + `"` + ".")
	}
	// localfilepath := localpath + samecommon.MakePathSeparatorsForThisOS(filepath)
	noexist := false
	var info os.FileInfo
	var localfilepath string
	if ourLocalStorage != "" {
		localfilepath = localpath + samecommon.MakePathSeparatorsForThisOS(ourLocalStorage)
		info, err = os.Stat(localfilepath)
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
	} else {
		noexist = true
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

func markFileDeleted(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *samecommon.AuthInfo, syncpublicid string, filepath string, modtime int64, filehash string) error {
	if verbose {
		fmt.Println("Marking file deleted:")
		fmt.Println("    Sync Point ID:", syncpublicid)
		fmt.Println("    File:", filepath)
		fmt.Println("    Remote hash:", filehash)
	}
	syncptid, localpath, err := determineAccessForSyncPoint(verbose, db, auth, syncpublicid, samecommon.AccessWrite)
	if err != nil {
		return err
	}
	fileid, _, ourFileHash, localstorage, err := getFileInfo(db, syncptid, filepath)
	if err != nil {
		return err
	}
	if verbose {
		fmt.Println("    Modification time:", modtime)
		fmt.Println("    Local hash:", filehash)
	}
	if ourFileHash != filehash {
		return errors.New("MarkFileDeleted: hashes do not match. To protect against accidental deletions, only the most recent version of the file (as known to the server) can be deleted. File:" + `"` + filepath + `"` + ".")
	}
	// localfilepath := localpath + string(os.PathSeparator) + samecommon.MakePathSeparatorsForThisOS(filepath)
	localfilepath := localpath + string(os.PathSeparator) + localstorage
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
	// We're actually going to ignore the error if one happens -- if the
	// file already doesn't exist, we don't care, and if there's some other
	// reason we can't delete it, there's nothing we can do about it anyway.
	if verbose {
		fmt.Println("Local file deleted. Deletion complete")
	}
	return nil
}

// Returns: new generated password. (Remember, users are not allowed to choose their own passwords.)
func resetUserPassword(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *samecommon.AuthInfo, username string) ([]byte, error) {
	fmt.Println("Resetting user password for:", username)
	cmd := "SELECT userid FROM user WHERE (username = ?);"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return nil, err
	}
	rows, err := stmtSel.Query(username)
	if err != nil {
		return nil, err
	}
	var userid int64
	userid = 0
	for rows.Next() {
		err = rows.Scan(&userid)
		if err != nil {
			return nil, err
		}
	}
	if auth.UserId == 0 {
		return nil, errors.New("ResetUserPassword: User " + `"` + username + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    User ID is:", userid)
	}
	if auth.UserId == 0 {
		return nil, errors.New("ResetUserPassword: Not logged in.")
	}
	if (auth.UserId & samecommon.RoleAdmin) == 0 {
		// not admin -- is user resetting their own password?
		if auth.UserId != userid {
			return nil, errors.New("ResetUserPassword: Permission denied.")
		}
	}
	// Ok, if we got here, we are going to proceed with the password reset
	passwordStore, passwordCR, pwsalt, pwhash, challengeresponsekey, err := generateUserPasswordSet()
	if err != nil {
		return nil, errors.New("ResetUserPassword: " + err.Error())
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	cmd = "UPDATE user SET pwsalt = ?, pwhash = ?, challengeresponsekey = ? WHERE userid = ?;"
	stmtUpd, err := tx.Prepare(cmd)
	_, err = stmtUpd.Exec(pwsalt, pwhash, challengeresponsekey, userid)
	if err != nil {
		return nil, err
	}
	err = tx.Commit()
	password := passwordPiecesToPassword(passwordStore, passwordCR)
	if verbose {
		fmt.Println("    Password reset to:", password)
	}
	return password, err
}

// This is a special function that should only be invoked from admin mode on the
// client and should only be needed when upgrading between incompatible
// versions or repairing things when things have gone horribly wrong (which
// should never happen). What it does is erase the complete set of hashes on the
// server and replace them in their entirety with a new set from the client.
func uploadAllHashes(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, auth *samecommon.AuthInfo, syncpublicid string, filepath []string, modtime []int64, filehash []string) error {
	if verbose {
		fmt.Println("Repair mode: Uploading all file hashes.")
	}
	cmd := "SELECT syncptid FROM syncpoint WHERE publicid = ?;"
	stmtSel, err := db.Prepare(cmd)
	if err != nil {
		return errors.New("uploadAllHashes: " + err.Error())
	}
	rows, err := stmtSel.Query(syncpublicid)
	if err != nil {
		return errors.New("uploadAllHashes: " + err.Error())
	}
	defer rows.Close()
	var syncptid int64
	syncptid = 0
	for rows.Next() {
		err = rows.Scan(&syncptid)
		if err != nil {
			return errors.New("uploadAllHashes: " + err.Error())
		}
	}
	if syncptid == 0 {
		return errors.New("uploadAllHashes: Sync point " + `"` + syncpublicid + `"` + " does not exist.")
	}
	if verbose {
		fmt.Println("    Sync point with public id: ", syncpublicid, "found, ID =", syncptid)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd = "DELETE FROM fileinfo WHERE syncptid = ?;"
	stmtDel, err := tx.Prepare(cmd)
	_, err = stmtDel.Exec(syncptid)
	if err != nil {
		return errors.New("uploadAllHashes: " + err.Error())
	}
	if verbose {
		fmt.Println("    All existing file info records cleared.")
	}
	numFiles := len(filepath)
	if verbose {
		fmt.Println("    Number of files is:", numFiles)
	}
	cmd = "INSERT INTO fileinfo (syncptid, filepath, modtime, filehash, reupneeded, localstorage) VALUES (?, ?, ?, ?, 0, '');"
	stmtIns, err := tx.Prepare(cmd)
	for ii := 0; ii < numFiles; ii++ {
		if verbose {
			fmt.Println("    Adding:", filepath[ii], "mod time", modtime[ii], "file hash", filehash[ii])
		}
		_, err = stmtIns.Exec(syncptid, filepath[ii], modtime[ii], filehash[ii])
		if err != nil {
			err2 := tx.Rollback()
			if err2 != nil {
				return err2
			} else {
				return err
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		return errors.New("uploadAllHashes: " + err.Error())
	}
	return nil
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

func unmReceiveFile(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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

func unmLogin(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("Login: Version number mismatch.")
	}
	username, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	password, err := rpc.GetByteArray(0, 0, 1)
	if err != nil {
		return err
	}
	err = login(verbose, db, wnet, auth, username, password)
	wrpc.SendReplyVoid("Login", version, errorToString(err), wnet)
	return nil
}

func unmListUsers(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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
		reply.AddRowColumnString(userlist[ii].Username)
		reply.AddRowColumnInt(int64(userlist[ii].Role))
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmAddUser(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("AddUser: Version number mismatch.")
	}
	username, err := rpc.GetString(0, 0, 0)
	if err != nil {
		fmt.Println("unmAdduser: username:", err)
		return err
	}
	role64, err := rpc.GetInt(0, 0, 1)
	if err != nil {
		fmt.Println("unmAdduser: role:", err)
		return err
	}
	role := int(role64)
	password, err := addUser(verbose, db, auth, username, role)
	reply := wrpc.NewDB()
	reply.StartDB("AddUserReply", 0, 1)
	reply.StartTable("", 2, 1)
	reply.AddColumn("", wrpc.ColByteArray)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnByteArray(password)
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmAddSyncPoint(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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

func unmListSyncPoints(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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
		reply.AddRowColumnString(syncpointlist[ii].PublicId)
		reply.AddRowColumnString(syncpointlist[ii].Path)
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmAddGrant(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("AddGrant: Version number mismatch.")
	}
	username, err := rpc.GetString(0, 0, 0)
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
	err = addGrant(verbose, db, auth, username, syncpublicid, access)
	return wrpc.SendReplyVoid("AddGrant", version, errorToString(err), wnet)
}

func unmListGrants(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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
		reply.AddRowColumnString(grantlist[ii].Username)
		reply.AddRowColumnString(grantlist[ii].PublicId)
		reply.AddRowColumnInt(int64(grantlist[ii].Access))
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmDeleteGrant(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("DeleteGrant: Version number mismatch.")
	}
	username, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	syncpublicid, err := rpc.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	err = deleteGrant(verbose, db, auth, username, syncpublicid)
	return wrpc.SendReplyVoid("DeleteGrant", version, errorToString(err), wnet)
}

func unmDeleteSyncPoint(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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

func unmDeleteUser(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("DeleteUser: Version number mismatch.")
	}
	username, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	err = deleteUser(verbose, db, auth, username)
	return wrpc.SendReplyVoid("DeleteUser", version, errorToString(err), wnet)
}

func unmGetServerTreeForSyncPoint(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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
		reply.AddRowColumnString(filelist[ii].FilePath)
		reply.AddRowColumnInt(int64(filelist[ii].FileTime))
		reply.AddRowColumnString(filelist[ii].FileHash)
		reply.AddRowColumnBool(filelist[ii].ReUpNeeded)
	}
	reply.StartTable("success", 1, 1)
	reply.AddColumn("success", wrpc.ColString)
	reply.StartRow()
	reply.AddRowColumnString(errorToString(err))
	err = reply.SendDB(wnet)
	return err
}

func unmSendFile(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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

func unmMarkFileDeleted(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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

func unmResetUserPassword(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("ResetUserPassword: Version number mismatch.")
	}
	username, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	password, err := resetUserPassword(verbose, db, wnet, auth, username)
	return wrpc.SendReplyScalarByteArray("ResetUserPassword", version, password, errorToString(err), wnet)
}

func unmUploadAllHashes(version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
	if version != 0 {
		return errors.New("UploadAllHashes: Version number mismatch.")
	}
	syncpublicid, err := rpc.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	numRows := rpc.GetNumRows(1)
	filepath := make([]string, numRows)
	modtime := make([]int64, numRows)
	filehash := make([]string, numRows)
	for ii := 0; ii < numRows; ii++ {
		filepath[ii], err = rpc.GetString(1, ii, 0)
		if err != nil {
			return err
		}
		modtime[ii], err = rpc.GetInt(1, ii, 1)
		if err != nil {
			return err
		}
		filehash[ii], err = rpc.GetString(1, ii, 2)
		if err != nil {
			return err
		}
	}
	err = uploadAllHashes(verbose, db, wnet, auth, syncpublicid, filepath, modtime, filehash)
	return wrpc.SendReplyVoid("UploadAllHashes", version, errorToString(err), wnet)
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

func dispatch(fcname string, version int, rpc wrpc.IWRPC, wnet wrpc.IWNetConnection, db *sql.DB, auth *samecommon.AuthInfo, verbose bool) error {
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
	case "UploadAllHashes":
		return unmUploadAllHashes(version, rpc, wnet, db, auth, verbose)
	default:
		if verbose {
			fmt.Println("Dispatch: ", fcname, "not found.")
		}
		fmt.Println("Function name is:", fcname)
		return errors.New("Dispatch failed: function " + `"` + fcname + `"` + " not found.")
	}
}

func handleConnection(conn net.Conn, verose bool, db *sql.DB, symkey []byte, hmackey []byte, verbose bool) {
	var auth samecommon.AuthInfo
	auth.UserId = 0
	auth.Role = 0
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

// ----------------------------------------------------------------
// end of functions that respond to network connections
// ----------------------------------------------------------------

// ----------------------------------------------------------------
// beginning of functions that respond to local user
// ----------------------------------------------------------------

func trim(stg string) string {
	return strings.Trim(stg, " \t\n\r")
}

// All these functions are for the "quick setup" configuration system
//
// functions getYesNo and getLine are different from the client versions in the error handling

func getYesNo(reader *bufio.Reader, prompt string) (bool, error) {
	result := false
	haveResult := false
	for !haveResult {
		fmt.Print(prompt)
		yesno, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		if len(yesno) > 0 {
			yesno = yesno[:1]
		}
		if (yesno == "Y") || (yesno == "y") {
			result = true
			haveResult = true
		}
		if (yesno == "N") || (yesno == "n") {
			result = false
			haveResult = true
		}
	}
	return result, nil
}

func getLine(reader *bufio.Reader) (string, error) {
	result, err := reader.ReadString('\n')
	return trim(result), err
}

func createDB(verbose bool, databaseFileName string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", databaseFileName)
	if err != nil {
		return db, err
	}
	err = initializeSettings(db)
	if err != nil {
		return db, err
	}
	err = initializeServerTables(db)
	if err != nil {
		return db, err
	}
	if verbose {
		fmt.Println("Database initialized.")
	}
	return db, nil
}

func setupPortNumber(verbose bool, db *sql.DB) error {
	portnum := 0
	for portnum == 0 {
		fmt.Print("Port: ")
		// fmt.Scanln(&ptStr)
		keyboard := bufio.NewReader(os.Stdin)
		ptStr, err := getLine(keyboard)
		if err != nil {
			return err
		}
		portnum = strToInt(ptStr)
	}
	samecommon.SetNameValuePair(db, "port", intToStr(portnum))
	if verbose {
		fmt.Println("Port number set to", portnum)
	}
	return nil
}

func setupServerKeys(verbose bool, db *sql.DB, outputKeys bool) error {
	symkey, err := samecommon.GenerateAESKey()
	if err != nil {
		return err
	}
	hmackey, err := samecommon.GenerateSHAKey()
	if err != nil {
		return err
	}
	if outputKeys {
		fmt.Print("Server key: ")
		fmt.Print(hex.EncodeToString(symkey))
		fmt.Println(hex.EncodeToString(hmackey))
	}
	samecommon.SetNameValuePair(db, "symmetrickey", hex.EncodeToString(symkey))
	samecommon.SetNameValuePair(db, "hmackey", hex.EncodeToString(hmackey))
	if verbose {
		fmt.Println("Symmetric key set to:", hex.EncodeToString(symkey))
		fmt.Println("HMAC key set to:", hex.EncodeToString(hmackey))
	}
	return nil
}

func setupQuickSetupSyncPoint(verbose bool, db *sql.DB) (string, error) {
	var err error
	path := ""
	for path == "" {
		fmt.Print("Directory path for sync point (relative path recommended): ")
		keyboard := bufio.NewReader(os.Stdin)
		path, err = getLine(keyboard)
		if err != nil {
			return "", err
		}
		dirEmpty, err := isDirEmpty(path, verbose)
		if err != nil {
			fmt.Println(err)
			path = ""
			dirEmpty = true // just to make following message go away
		}
		if !dirEmpty {
			fmt.Println("The directory you specified is not empty.")
			path = ""
		}
	}
	if verbose {
		fmt.Println("Adding sync point with path", path)
	}
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	cmd := "SELECT syncptid FROM syncpoint WHERE path = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return "", err
	}
	rowsExisting, err := stmtSelExisting.Query(path)
	if err != nil {
		return "", err
	}
	defer rowsExisting.Close()
	var syncptid int64
	syncptid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&syncptid)
		if err != nil {
			return "", err
		}
	}
	var publicid string
	if syncptid == 0 {
		publicIdBin, err := generateSyncPointId()
		if err != nil {
			return "", err
		}
		publicid = hex.EncodeToString(publicIdBin)
		cmd = "INSERT INTO syncpoint (publicid, path) VALUES (?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return "", err
		}
		_, err = stmtIns.Exec(publicid, path)
		if err != nil {
			return "", err
		}
	} else {
		err = tx.Rollback()
		if err != nil {
			return "", err
		}
		return "", errors.New("Sync point already exists.") // this should be IMPOSSIBLE in Quick Setup!
	}
	err = tx.Commit()
	if err != nil {
		return "", err
	}
	if verbose {
		fmt.Println("    Sync point created with path:", path)
		fmt.Println("    Public ID:", publicid)
	}
	return publicid, nil
}

func createBuiltInGrant(verbose bool, db *sql.DB, username string, syncpublicid string, access int) error {
	if verbose {
		fmt.Println("Creating built-in grant to access to sync point for user.")
		fmt.Println("    Username (email):", username)
		fmt.Println("    Sync point ID:", syncpublicid)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "SELECT userid FROM user WHERE username = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err := stmtSelExisting.Query(username)
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
	if userid == 0 {
		err = tx.Rollback()
		if err != nil {
			return errors.New("addGrant: " + err.Error())
		}
		return errors.New("Username (email) " + `"` + username + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found username.")
	}
	cmd = "SELECT syncptid FROM syncpoint WHERE publicid = ?;"
	stmtSelExisting, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err = stmtSelExisting.Query(syncpublicid)
	if err != nil {
		return err
	}
	defer rowsExisting.Close()
	var syncptid int64
	syncptid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&syncptid)
		if err != nil {
			return err
		}
	}
	if syncptid == 0 {
		err = tx.Rollback()
		if err != nil {
			return err
		}
		return errors.New("Share point ID " + `"` + syncpublicid + `"` + " not found.")
	}
	if verbose {
		fmt.Println("    Found share point ID.")
	}
	cmd = "SELECT grantid FROM grant WHERE (syncptid = ?) AND (userid = ?);"
	stmtSelExisting, err = tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err = stmtSelExisting.Query(syncptid, userid)
	if err != nil {
		return err
	}
	defer rowsExisting.Close()
	var grantid int64
	grantid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&grantid)
		if err != nil {
			return err
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
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	if verbose {
		fmt.Println("    User granted access to share.")
	}
	return nil
}

func main() {
	vflag := flag.Bool("v", false, "verbose mode")
	gflag := flag.Bool("g", false, "generate key")
	kflag := flag.Bool("k", false, "show existing key")
	iflag := flag.Bool("i", false, "initialize")
	pflag := flag.Bool("p", false, "configure port number")
	aflag := flag.Bool("a", false, "create admin account")
	qflag := flag.Bool("q", false, "quick setup")
	flag.Parse()
	verbose := *vflag
	configurePort := *pflag
	generateKeys := *gflag
	initialize := *iflag
	showKeys := *kflag
	createAdmin := *aflag
	quickSetup := *qflag
	if verbose {
		fmt.Println("samed version 0.5.11")
		fmt.Println("Flags:")
		fmt.Println("    Generate key mode:", onOff(generateKeys))
		fmt.Println("    Initialize:", onOff(initialize))
		fmt.Println("    Show keys:", onOff(showKeys))
		fmt.Println("    Create admin:", onOff(createAdmin))
		fmt.Println("    Quick setup:", onOff(quickSetup))
	}
	if quickSetup {
		exist, err := samecommon.FileExists(databaseFileName)
		if exist {
			fmt.Println("It looks like a samesync server (samed) database already exists in this")
			fmt.Println("directory. samed does not need to be set up twice on the same server.")
			return
		}
		fmt.Println("Welcome to the samesync server (samed) quick setup process. You will need the")
		fmt.Println("following pieces of information:")
		fmt.Println("")
		fmt.Println("1. The port number the server will run as. The port needs to be open by the OS")
		fmt.Println("   and any relevant firewalls.")
		fmt.Println("")
		fmt.Println("2. The directory on the server where files in the syncronized directory will be")
		fmt.Println("   stored. Relative paths (relative to this directory where you are starting")
		fmt.Println("   samed) are recommended, because they make it easier to move to a different")
		fmt.Println("   physical machine if you should ever need to do so. The directory needs to")
		fmt.Println("   allready created before you run quick setup. It also needs to be empty.")
		fmt.Println("")
		fmt.Println("The quick setup system will create a configuration file that you can take to")
		fmt.Println("client machines to set them up quickly. This configuration file contains")
		fmt.Println("encryption keys and must be securely transported across the network (or")
		fmt.Println("physically, such as by carrying a USB stick).")
		fmt.Println("")
		fmt.Println("To make it harder to gain access if someone should accidentally get hold of a")
		fmt.Println("configuration file, the name/IP address of the server and the port number are")
		fmt.Println("not stored in the file. You will still need to type these in manually at each")
		fmt.Println("client.")
		fmt.Println("")
		keyboard := bufio.NewReader(os.Stdin)
		yes, err := getYesNo(keyboard, "Do you wish to proceed? (y/n) ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if !yes {
			return
		}
		//
		// 1. Create db
		//
		db, err := createDB(verbose, databaseFileName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer db.Close()
		//
		// 2. Set port
		//
		err = setupPortNumber(verbose, db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		//
		// 3. Generate server keys
		//
		err = setupServerKeys(verbose, db, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		//
		// 4. Create "everybody" account
		//
		password, err := createBuiltInAccount(verbose, db, "everybody", samecommon.RoleSyncPointUser)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		//
		// 5. Create syncpoint
		//
		publicid, err := setupQuickSetupSyncPoint(verbose, db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		//
		// 6. Grant user "everybody" access to syncpoint
		//
		access := samecommon.AccessRead | samecommon.AccessWrite
		err = createBuiltInGrant(verbose, db, "everybody", publicid, access)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		//
		// 7. Write out port, server key, and "everybody" password to config file.
		//
		fhConfig, err := os.Create("samesetup.txt")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		err = samecommon.SetupWriteSettingToConfigFile(fhConfig, "username", "everybody")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		err = samecommon.SetupWriteSettingToConfigFile(fhConfig, "password", password)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		err = samecommon.SetupWriteSettingToConfigFile(fhConfig, "syncpointid", publicid)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		serversymkey, err := samecommon.GetValue(db, "symmetrickey", "missing")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		err = samecommon.SetupWriteSettingToConfigFile(fhConfig, "serversymkey", serversymkey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		serverhmackey, err := samecommon.GetValue(db, "hmackey", "missing")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		err = samecommon.SetupWriteSettingToConfigFile(fhConfig, "serverhmackey", serverhmackey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fhConfig.Close()
		//
		// 8. Closing instructions to user
		//
		fmt.Println("")
		fmt.Println("You should now have a file called samesetup.txt. Take this file to your client")
		fmt.Println("machines, put it one directory UP from the directory you want to sync (so it is")
		fmt.Println("../samesetup.txt when you run the program) and run " + `"` + "same -q" + `"` + ". If you put the")
		fmt.Println("file somewhere other than ../samesetup.txt you will need to specify the file path with")
		fmt.Println(`"` + "same -q -f <file>" + `"` + ".")
		fmt.Println("")
		fmt.Println(" The first client where you run same -q will add the end-to-end key to the file.")
		fmt.Println("This is done at the client so you know the server never has access to the key.")
		fmt.Println("Once the end-to-end key has been added, you can take that version of the file")
		fmt.Println("to all other clients.")
		fmt.Println("")
		fmt.Println("After all clients are set up, the samesetup.txt files should be deleted.")
		fmt.Println("")
		return
	}
	if initialize {
		exist, err := samecommon.FileExists(databaseFileName)
		if exist {
			fmt.Println("Looks like the database file has already been created.")
			return
		}
		db, err := createDB(verbose, databaseFileName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer db.Close()
		fmt.Println("Initialized.")
		return
	}
	exist, err := samecommon.FileExists(databaseFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if !exist {
		fmt.Println("No " + databaseFileName + " file found. Either you are in the wrong directory, or you have not initialized the system. Use samed -i to initialize.")
		return
	}
	db, err := sql.Open("sqlite3", databaseFileName)
	defer db.Close()
	if generateKeys {
		err = setupServerKeys(verbose, db, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		return
	}
	if createAdmin {
		_, err := createBuiltInAccount(verbose, db, "admin", samecommon.RoleAdmin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		return
	}
	if configurePort {
		err = setupPortNumber(verbose, db)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	//
	// If we got here, configuration stuff should be done, let's see if we can load everything we need
	//
	ptNum, err := samecommon.GetValue(db, "port", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("Port number:", ptNum)
	}
	portnum := strToInt(ptNum)
	if portnum == 0 {
		fmt.Println("Port number has not been set.")
		fmt.Println("Use samed -p to configure the port number")
		return
	}
	symKeyStr, err := samecommon.GetValue(db, "symmetrickey", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("Symmetric key", symKeyStr)
	}
	hmacKeyStr, err := samecommon.GetValue(db, "hmackey", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("HMAC key", hmacKeyStr)
	}
	symkey, err := hex.DecodeString(symKeyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	hmackey, err := hex.DecodeString(hmacKeyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if showKeys {
		fmt.Print("Server key: ")
		fmt.Print(hex.EncodeToString(symkey))
		fmt.Println(hex.EncodeToString(hmackey))
		return
	}
	if (len(symkey) == 0) || (len(hmackey) == 0) {
		fmt.Println("Key has not been set up.")
		fmt.Println("Use samed -g to generate key.")
		fmt.Println("Use samed -k to export key for clients.")
		return
	}
	//
	// if we got here, we're going to listen for incoming connections!
	//
	listener, err := net.Listen("tcp", ":"+intToStr(portnum))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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
