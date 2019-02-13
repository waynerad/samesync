package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"wrpc"
)

// "crypto/rand"
// "encoding/base64"

type wfileInfo struct {
	filePath string
	fileSize int64
	fileTime int64
	fileHash string
}

type wfileSortSlice struct {
	theSlice []wfileInfo
}

const roleAdmin = 1
const roleSyncPointUser = 2

const accessRead = 1
const accessWrite = 2

const databaseFileName = "samestate.db"
const tempFileName = "temp.temp"

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func intToStr(ii int) string {
	return strconv.FormatInt(int64(ii), 10)
}

func int64ToStr(ii int64) string {
	return strconv.FormatInt(ii, 10)
}

func strToInt(stg string) int {
	ii, err := strconv.ParseInt(stg, 10, 64)
	if err != nil {
		return 0
	}
	return int(ii)
}

func trim(stg string) string {
	return strings.Trim(stg, " \t\n\r")
}

// func defaultKeys() ([]byte, []byte) {
//	symmetricKey, _ := hex.DecodeString("a9672b783092f3f3049a5764d1c906f4d96e4914cf6b549d94280ee0f0814d56")
//	hmacKey, _ := hex.DecodeString("84982f4a55885d7dfff30d72dcf74ad3b309683d4ac89935fddeca40efdc7ce4")
//	return symmetricKey, hmacKey
// }

func openConnection(symmetricKey []byte, hmacKey []byte, remoteHost string, portNumber int) (wrpc.IWNetConnection, error) {
	wnet := wrpc.NewConnection()
	wnet.SetDest(remoteHost, portNumber)
	wnet.SetKeys(symmetricKey, hmacKey)
	err := wnet.Open()
	return wnet, err
}

func standardReply(wnet wrpc.IWNetConnection, fcname string) (wrpc.IWRPC, error) {
	replmsg, err := wnet.NextMessage()
	if err != nil {
		return nil, err
	}
	if len(replmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		return nil, errors.New("Connection closed by same server.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(replmsg)
	if reply.GetDBName() != fcname+"Reply" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			return nil, errors.New(reply.GetDBName())
		}
		return nil, errors.New(reply.GetDBName() + ": " + errmsg)
	}
	return reply, nil
}

func getLocalTime() int64 {
	now := time.Now()
	result := now.UnixNano()
	return result
}

func standardStringReply(wnet wrpc.IWNetConnection, fcname string) (string, string, error) {
	reply, err := standardReply(wnet, fcname)
	if err != nil {
		return "", "", err
	}
	result, err := reply.GetString(0, 0, 0)
	if err != nil {
		return "", "", err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return result, "", err
	}
	return result, errmsg, nil
}

func standardVoidReply(wnet wrpc.IWNetConnection, fcname string) (string, error) {
	reply, err := standardReply(wnet, fcname)
	if err != nil {
		return "", err
	}
	errmsg, err := reply.GetString(0, 0, 0)
	if err != nil {
		return "", err
	}
	return errmsg, nil
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

// This function converts all path separators to whatever our actual OS uses
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

func stashFileInfo(db *sql.DB, filepath string, filesize int64, filetime int64, filehash string) error {
	filepath = makePathSeparatorsStandard(filepath)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd := "SELECT fileid FROM fileinfo WHERE filepath = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	if err != nil {
		return err
	}
	rowsExisting, err := stmtSelExisting.Query(filepath)
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
		cmd = "INSERT INTO fileinfo (filepath, filesize, filetime, filehash) VALUES (?, ?, ?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		if err != nil {
			return err
		}
		_, err = stmtIns.Exec(filepath, filesize, filetime, filehash)
		if err != nil {
			return err
		}
	} else {
		cmd = "UPDATE fileinfo SET filetime = ?, filehash = ? WHERE fileid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(filetime, filehash, fileid)
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	return err
}

// ----------------------------------------------------------------
// Remote calls
// ----------------------------------------------------------------

func rpcGetTime(wnet wrpc.IWNetConnection) (int64, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("GetTime", 0, 1)
	rpc.StartTable("", 0, 0)
	rpc.StartRow()
	err := rpc.SendDB(wnet)
	if err != nil {
		return 0, err
	}
	reply, err := standardReply(wnet, "GetTime")
	if err != nil {
		return 0, err
	}
	result, err := reply.GetInt(0, 0, 0)
	if err != nil {
		return 0, err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return 0, err
	}
	if errmsg == "" {
		return result, nil
	}
	return result, errors.New(errmsg)
}

func rpcLogin(wnet wrpc.IWNetConnection, email string, password string) (string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("Login", 0, 1)
	rpc.StartTable("", 2, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(email)
	rpc.AddRowColumnString(password)
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	errmsg, err := standardVoidReply(wnet, "Login")
	return errmsg, err
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

func rpcListUsers(wnet wrpc.IWNetConnection) string {
	rpc := wrpc.NewDB()
	rpc.StartDB("ListUsers", 0, 0)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err.Error()
	}
	reply, err := standardReply(wnet, "ListUsers")
	if err != nil {
		return err.Error()
	}
	num := reply.GetNumRows(0)
	for ii := 0; ii < num; ii++ {
		email, err := reply.GetString(0, ii, 0)
		if err != nil {
			return err.Error()
		}
		role64, err := reply.GetInt(0, ii, 1)
		if err != nil {
			return err.Error()
		}
		role := int(role64)
		fmt.Println(email, "-", roleFlagsToString(role))
	}
	errmsg, err := reply.GetString(1, 0, 0)
	if err != nil {
		return err.Error()
	}
	return errmsg
}

func rpcAddUser(wnet wrpc.IWNetConnection, email string, role int) (string, string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("AddUser", 0, 1)
	rpc.StartTable("", 2, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColInt)
	rpc.StartRow()
	rpc.AddRowColumnString(email)
	rpc.AddRowColumnInt(int64(role))
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", "", err
	}
	reply, err := standardReply(wnet, "AddUser")
	if err != nil {
		return "", "", err
	}
	password, err := reply.GetString(0, 0, 0)
	if err != nil {
		return "", "", err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return "", "", err
	}
	return password, errmsg, nil
}

func rpcAddSyncPoint(wnet wrpc.IWNetConnection, path string) (string, string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("AddSyncPoint", 0, 1)
	rpc.StartTable("", 0, 0)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(path)
	rpc.SendDB(wnet)
	reply, err := standardReply(wnet, "AddSyncPoint")
	if err != nil {
		return "", "", err
	}
	publicid, err := reply.GetString(0, 0, 0)
	if err != nil {
		return "", "", err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return "", "", err
	}
	return publicid, errmsg, err
}

func rpcListSyncPoints(wnet wrpc.IWNetConnection, server string) string {
	rpc := wrpc.NewDB()
	rpc.StartDB("ListSyncPoints", 0, 0)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err.Error()
	}
	reply, err := standardReply(wnet, "ListSyncPoints")
	if err != nil {
		return err.Error()
	}
	num := reply.GetNumRows(0)
	for ii := 0; ii < num; ii++ {
		publicid, err := reply.GetString(0, ii, 0)
		if err != nil {
			return err.Error()
		}
		path, err := reply.GetString(0, ii, 1)
		if err != nil {
			return err.Error()
		}
		target := "//" + server
		if path[0] == '/' {
			target += path
		} else {
			target += "/" + path
		}
		fmt.Println(publicid, "->", target)
	}
	errmsg, err := reply.GetString(1, 0, 0)
	if err != nil {
		return err.Error()
	}
	return errmsg
}

func rpcAddGrant(wnet wrpc.IWNetConnection, email string, syncpublicid string, access int) (string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("AddGrant", 0, 1)
	rpc.StartTable("", 0, 0)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColInt)
	rpc.StartRow()
	rpc.AddRowColumnString(email)
	rpc.AddRowColumnString(syncpublicid)
	rpc.AddRowColumnInt(int64(access))
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	errmsg, err := standardVoidReply(wnet, "AddGrant")
	return errmsg, err
}

func rpcListGrants(wnet wrpc.IWNetConnection) string {
	rpc := wrpc.NewDB()
	rpc.StartDB("ListGrants", 0, 0)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err.Error()
	}
	reply, err := standardReply(wnet, "ListGrants")
	if err != nil {
		return err.Error()
	}
	num := reply.GetNumRows(0)
	for ii := 0; ii < num; ii++ {
		email, err := reply.GetString(0, ii, 0)
		if err != nil {
			return err.Error()
		}
		publicid, err := reply.GetString(0, ii, 1)
		if err != nil {
			return err.Error()
		}
		access64, err := reply.GetInt(0, ii, 2)
		if err != nil {
			return err.Error()
		}
		access := int(access64)
		fmt.Println(email, "-> has access to sync point ->", publicid, "-> with permissions:", accessFlagsToString(access))
	}
	errmsg, err := reply.GetString(1, 0, 0)
	if err != nil {
		return err.Error()
	}
	return errmsg
}

func rpcDeleteUser(wnet wrpc.IWNetConnection, email string) (string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("DeleteUser", 0, 1)
	rpc.StartTable("", 1, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(email)
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	errmsg, err := standardVoidReply(wnet, "DeleteUser")
	return errmsg, err
}

func rpcDeleteSyncPoint(wnet wrpc.IWNetConnection, path string) (string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("DeleteSyncPoint", 0, 1)
	rpc.StartTable("", 1, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(path)
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	errmsg, err := standardVoidReply(wnet, "DeleteSyncPoint")
	return errmsg, err
}

func rpcDeleteGrant(wnet wrpc.IWNetConnection, email string, syncpublicid string) (string, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("DeleteGrant", 0, 1)
	rpc.StartTable("", 2, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(email)
	rpc.AddRowColumnString(syncpublicid)
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	errmsg, err := standardVoidReply(wnet, "DeleteGrant")
	return errmsg, err
}

func rpcGetServerTreeForSyncPoint(wnet wrpc.IWNetConnection, syncpublicid string) ([]wfileInfo, error) {
	rpc := wrpc.NewDB()
	rpc.StartDB("GetServerTreeForSyncPoint", 0, 1)
	rpc.StartTable("", 0, 0)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(syncpublicid)
	err := rpc.SendDB(wnet)
	if err != nil {
		return nil, err
	}
	reply, err := standardReply(wnet, "GetServerTreeForSyncPoint")
	if err != nil {
		return nil, err
	}
	errmsg, err := reply.GetString(1, 0, 0)
	if err != nil {
		return nil, err
	}
	if errmsg != "" {
		return nil, errors.New(errmsg)
	}
	num := reply.GetNumRows(0)
	result := make([]wfileInfo, 0)
	for ii := 0; ii < num; ii++ {
		filepath, err := reply.GetString(0, ii, 0)
		if err != nil {
			return nil, err
		}
		filetime, err := reply.GetInt(0, ii, 1)
		if err != nil {
			return nil, err
		}
		filehash, err := reply.GetString(0, ii, 2)
		if err != nil {
			return nil, err
		}
		result = append(result, wfileInfo{filepath, 0, filetime, filehash})
	}
	return result, nil
}

func sendFile(wnet wrpc.IWNetConnection, syncpublicid string, localdir string, localfilepath string, filehash string, serverTimeOffset int64) string {
	info, err := os.Stat(localfilepath)
	if err != nil {
		panic(err)
	}
	if info.IsDir() {
		panic("File given to transfer is a directory")
	}
	//
	// Step 1: Call ReceiveFile API on remote server, tell them the
	// name of the file we're going to send and how big it is
	msg := wrpc.NewDB()
	msg.StartDB("ReceiveFile", 0, 1)
	msg.StartTable("", 5, 1)
	msg.AddColumn("syncpublicid", wrpc.ColString)
	msg.AddColumn("filepath", wrpc.ColString)
	msg.AddColumn("size", wrpc.ColInt)
	msg.AddColumn("modtime", wrpc.ColInt)
	msg.AddColumn("filehash", wrpc.ColString)
	//
	// filename := info.Name()
	remotefilepath := localfilepath[len(localdir):]
	modtime := info.ModTime().UnixNano() + serverTimeOffset
	//
	msg.StartRow()
	msg.AddRowColumnString(syncpublicid)
	msg.AddRowColumnString(remotefilepath)
	msg.AddRowColumnInt(info.Size())
	msg.AddRowColumnInt(modtime)
	msg.AddRowColumnString(filehash)
	msg.SendDB(wnet)
	//
	// Step 2: Get a reply back saying "Go Ahead"
	// If we don't get the "Go Ahead And Send", we don't send the file
	rplmsg, err := wnet.NextMessage()
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		panic("Connection closed by same server.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	if reply.GetDBName() != "ReceiveFileReply" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			panic(err)
		}
		panic(errors.New(reply.GetDBName() + ": " + errmsg))
	}
	result, err := reply.GetString(0, 0, 0)
	if err != nil {
		panic(err)
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		panic(err)
	}
	if result != "GoAheadAndSend" {
		fmt.Println("Something is wrong. Not sending file.")
		panic(errors.New(errmsg))
	}
	//
	// Step 3: Actually send the file
	// For this we send the bytes in "shove" mode, instead of using the Mini-DB RPC system
	// It's gets pushed through the crypto system, so don't worry,
	// the bits on the wire are still encrypted
	buffer := make([]byte, 32768)
	ciphertext := make([]byte, 32768) // allocated here as a memory management optimization
	//
	fh, err := os.Open(makePathSeparatorsForThisOS(localfilepath))
	if err != nil {
		panic(err)
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
				panic(err)
			}
		}
	}
	fh.Close()
	//
	// Step 4: Get reply from the remote end that the bytes were
	// received and the signature checked out
	rplmsg, err = wnet.NextMessage()
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		panic("Connection closed by same server.")
	}
	reply = wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	result, err = reply.GetString(0, 0, 0)
	if err != nil {
		panic(err)
	}
	errmsg, err = reply.GetString(0, 0, 1)
	if err != nil {
		panic(err)
	}
	return result
}

func retrieveFile(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, syncpublicid string, localdir string, localfilepath string, filehash string, serverTimeOffset int64) string {
	if verbose {
		fmt.Println("Seeking to update file:", localfilepath)
	}
	version := 0
	//
	// Step 1: Call SendFile API on remote server, tell them the
	// name of the file we want
	msg := wrpc.NewDB()
	msg.StartDB("SendFile", 0, 1)
	msg.StartTable("", 3, 1)
	msg.AddColumn("syncpublicid", wrpc.ColString)
	msg.AddColumn("filepath", wrpc.ColString)
	msg.AddColumn("filehash", wrpc.ColString)
	remotefilepath := localfilepath[len(localdir):]
	if verbose {
		fmt.Println("    Requesting retrieval of:", remotefilepath)
	}
	msg.StartRow()
	msg.AddRowColumnString(syncpublicid)
	msg.AddRowColumnString(remotefilepath)
	msg.AddRowColumnString(filehash)
	msg.SendDB(wnet)
	//
	// Step 2: Get reply telling us the size of the file we're
	// going to receive
	replmsg, err := wnet.NextMessage()
	if err != nil {
		panic(err)
		return err.Error()
	}
	if len(replmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		return "Connection closed by same server."
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(replmsg)
	if verbose {
		fmt.Println("    Reply received:", reply.GetDBName())
	}
	if reply.GetDBName() != "ReceiveFile" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			panic(err)
			return reply.GetDBName()
		}
		return reply.GetDBName() + ": " + errmsg
	}
	filepath, err := reply.GetString(0, 0, 0)
	if err != nil {
		return err.Error()
	}
	filesize, err := reply.GetInt(0, 0, 1)
	if err != nil {
		return err.Error()
	}
	modtime, err := reply.GetInt(0, 0, 2)
	if err != nil {
		return err.Error()
	}
	receiveFileHash, err := reply.GetString(0, 0, 3)
	if err != nil {
		return err.Error()
	}
	modtime -= serverTimeOffset
	if verbose {
		fmt.Println("    File being sent from server:", filepath)
		fmt.Println("    File size:", filesize)
		fmt.Println("    Last modified time:", modtime)
		fmt.Println("    File hash:", receiveFileHash)
	}
	if receiveFileHash != filehash {
		return "Received file hash does not match expected file hash."
	}
	//
	// Step 3: Send ReceiveFileReply with "GoAheadAndSend"
	err = wrpc.SendReplyScalarString("ReceiveFile", version, "GoAheadAndSend", "", wnet)
	if err != nil {
		return err.Error()
	}
	//
	// Step 4: Actually receive the bytes of the file
	// while the reply is headed out, we go ahead and start reading
	// the actual file bytes coming in
	var fhOut *os.File
	if verbose {
		fmt.Println("    Attempting to output to file:", localdir, string(os.PathSeparator)+tempFileName)
	}
	fhOut, err = os.Create(makePathSeparatorsForThisOS(localdir + string(os.PathSeparator) + tempFileName))
	if err != nil {
		return "receiveFile: " + err.Error()
	}
	var bytesread int64
	bytesread = 0
	const bufferSize = 65536
	// const bufferSize = 32768
	buffer := make([]byte, bufferSize)
	ciphertext := make([]byte, bufferSize)
	var nIn int
	var nOut int
	for bytesread < filesize {
		lrest := filesize - bytesread
		if lrest > bufferSize {
			nIn, err = wnet.PullBytes(buffer, ciphertext)
		} else {
			nIn, err = wnet.PullBytes(buffer[:lrest], ciphertext[:lrest])
		}
		if err != nil {
			return "receiveFile: " + err.Error()
		}
		nOut, err = fhOut.Write(buffer[:nIn])
		if err != nil {
			return "receiveFile: " + err.Error()
		}
		if nOut != nIn {
			return "Could no write entire buffer out to file for some unknown reason."
		}
		bytesread += int64(nIn)
	}
	fhOut.Close()
	if verbose {
		fmt.Println("    File received.")
	}
	//
	// Step 5: Now that we have the bytes of the file, rename the
	// file into place, removing the existing file that we have
	// preserved up until this time in case something went wrong
	if verbose {
		fmt.Println("    Renaming", localdir+string(os.PathSeparator)+tempFileName, "to", localdir+makePathSeparatorsForThisOS(filepath))
	}
	finalDestinationPath := makePathSeparatorsForThisOS(localdir + filepath)
	err = os.Rename(localdir+string(os.PathSeparator)+tempFileName, finalDestinationPath)
	if err != nil {
		mkerr := makePathForFile(localdir + makePathSeparatorsForThisOS(filepath))
		if mkerr != nil {
			return "receiveFile: " + err.Error()
		}
		mverr := os.Rename(localdir+string(os.PathSeparator)+tempFileName, finalDestinationPath)
		if mverr != nil {
			return "receiveFile: " + err.Error()
		}
	}
	//
	// Step 6: Stash all the info about the file in our local database
	if verbose {
		fmt.Println("    Storing updated file time and hash.")
	}
	// We have to get the exact time and size from our disk to keep
	// our local tree scanner from getting confused
	// we take the remote server's word for the file hash, though.
	finalInfo, err := os.Stat(finalDestinationPath)
	if err != nil {
		return err.Error()
	}
	finalFileSize := finalInfo.Size()
	finalModTime := finalInfo.ModTime().UnixNano()
	err = stashFileInfo(db, filepath, finalFileSize, finalModTime, filehash)
	if err != nil {
		return "receiveFile: " + err.Error()
	}
	if verbose {
		fmt.Println("    Sending reception complete message.")
	}
	//
	// Step 7: Tell the server we received the file successfully
	result := "ReceptionComplete"
	errmsg := ""
	wrpc.SendReplyScalarString("ReceiveFile", version, result, errmsg, wnet)
	if verbose {
		fmt.Println("    Reception complete.")
	}
	return errmsg
}

func rpcMarkFileDeleted(wnet wrpc.IWNetConnection, syncpublicid string, filepath string, filehash string) (string, error) {
	modtime := time.Now().UnixNano()
	rpc := wrpc.NewDB()
	rpc.StartDB("MarkFileDeleted", 0, 1)
	rpc.StartTable("", 4, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColInt)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(syncpublicid)
	rpc.AddRowColumnString(filepath)
	rpc.AddRowColumnInt(modtime)
	rpc.AddRowColumnString(filehash)
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	errmsg, err := standardVoidReply(wnet, "MarkFileDeleted")
	return errmsg, err
}

// ----------------------------------------------------------------
// End of remote calls
// ----------------------------------------------------------------

func onOff(bv bool) string {
	if bv {
		return "ON"
	} else {
		return "OFF"
	}
}

func fileExists(filepath string) bool {
	fhFile, err := os.Open(makePathSeparatorsForThisOS(filepath))
	if err != nil {
		message := err.Error()
		if message[len(message)-25:] == "no such file or directory" {
			return false
		}
		checkError(err)
	}
	err = fhFile.Close()
	checkError(err)
	return true
}

func findRootPath(currentPath string, fileToFind string) string {
	if fileExists(currentPath + string(os.PathSeparator) + fileToFind) {
		return currentPath
	}
	match := os.PathSeparator
	stack := make([]int, 0)
	sp := 0
	for idx, chr := range currentPath {
		if chr == match {
			stack = append(stack, idx)
			sp++
		}
	}
	for sp > 0 {
		sp--
		if fileExists(currentPath[:stack[sp]+1] + fileToFind) {
			return currentPath[:stack[sp]]
		}
	}
	return ""
}

func getStateDB(currentPath string, useFile string, defaultStateFileName string, verbose bool) (string, *sql.DB, error) {
	if verbose {
		fmt.Println("Current Path:", currentPath)
		if useFile != "" {
			fmt.Println("File to use (manual user override):", useFile)
		}
	}
	rootPath := findRootPath(currentPath, defaultStateFileName)
	if verbose {
		fmt.Println("Root path is:", rootPath)
	}
	var dbFile string
	if useFile != "" {
		dbFile = useFile
	} else {
		dbFile = rootPath + string(os.PathSeparator) + databaseFileName
	}
	if verbose {
		fmt.Println("Database file is:", dbFile)
	}
	if rootPath == "" {
		return "", nil, errors.New("State file not found. Looks like we are not in a directory tree that is being synchronized.")
	}
	db, err := sql.Open("sqlite3", dbFile)
	checkError(err)
	// defer db.Close()
	return rootPath, db, err
}

func initializeDatabase(db *sql.DB) {
	tx, err := db.Begin()
	checkError(err)
	cmd := "CREATE TABLE settings (nvpairid INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(255) NOT NULL, value VARCHAR(255) NOT NULL);"
	stmtCreate, err := tx.Prepare(cmd)
	checkError(err)
	_, err = stmtCreate.Exec()
	checkError(err)
	cmd = "CREATE INDEX idx_sett_nm ON settings (name);"
	stmtIndex, err := tx.Prepare(cmd)
	checkError(err)
	_, err = stmtIndex.Exec()
	checkError(err)

	cmd = "CREATE TABLE fileinfo (fileid INTEGER PRIMARY KEY AUTOINCREMENT, filepath TEXT NOT NULL, filesize INTEGER NOT NULL, filetime INTEGER NOT NULL, filehash TEXT NOT NULL);"
	stmtCreate, err = tx.Prepare(cmd)
	checkError(err)
	_, err = stmtCreate.Exec()
	checkError(err)
	cmd = "CREATE INDEX idx_file_pth ON fileinfo (filepath);"
	stmtIndex, err = tx.Prepare(cmd)
	checkError(err)
	_, err = stmtIndex.Exec()
	checkError(err)
	err = tx.Commit()
	checkError(err)
}

func setNameValuePair(db *sql.DB, name string, value string, verbose bool, protectExistingValue bool) {
	tx, err := db.Begin()
	checkError(err)
	cmd := "SELECT nvpairid FROM settings WHERE name = ?;"
	stmtSelExisting, err := tx.Prepare(cmd)
	checkError(err)
	rowsExisting, err := stmtSelExisting.Query(name)
	checkError(err)
	defer rowsExisting.Close()
	var nvpairid int64
	nvpairid = 0
	for rowsExisting.Next() {
		err = rowsExisting.Scan(&nvpairid)
		checkError(err)
	}
	if nvpairid == 0 {
		cmd = "INSERT INTO settings (name, value) VALUES (?, ?);"
		stmtIns, err := tx.Prepare(cmd)
		checkError(err)
		_, err = stmtIns.Exec(name, value)
		checkError(err)
	} else {
		if protectExistingValue {
			tx.Rollback()
			return
		}
		cmd = "UPDATE settings SET value = ? where nvpairid = ?;"
		stmtUpd, err := tx.Prepare(cmd)
		_, err = stmtUpd.Exec(value, nvpairid)
		checkError(err)
	}
	err = tx.Commit()
	checkError(err)
	if verbose {
		fmt.Println("Set configuration setting:", name, "=", value)
	}
}

func getValue(db *sql.DB, name string, defval string, verbose bool) string {
	var value string
	value = defval
	cmd := "SELECT value FROM settings WHERE name = ?;"
	stmtSel, err := db.Prepare(cmd)
	checkError(err)
	rows, err := stmtSel.Query(name)
	checkError(err)
	for rows.Next() {
		err = rows.Scan(&value)
		checkError(err)
	}
	if verbose {
		fmt.Println(name, "=", value)
	}
	return value
}

func showConfiguration(db *sql.DB, verbose bool) {
	server := getValue(db, "server", "", verbose)
	ptStr := getValue(db, "port", "0", verbose)
	port := strToInt(ptStr)
	email := getValue(db, "email", "", verbose)
	password := getValue(db, "password", "", false)
	syncPointID := getValue(db, "syncpointid", "", verbose)
	fmt.Println("Server:", server)
	fmt.Println("Port:", port)
	fmt.Println("Email:", email)
	fmt.Println("Password:", password)
	fmt.Println("Sync point ID:", syncPointID)

	serverSymKey := getValue(db, "serversymkey", "", verbose)
	if serverSymKey != "" {
		fmt.Println("Server key:")
		fmt.Println(serverSymKey)
	}
	serverHmacKey := getValue(db, "serverhmackey", "", verbose)
	if serverHmacKey != "" {
		fmt.Println(serverHmacKey)
	}

	endToEndSymKey := getValue(db, "endtoendsymkey", "", verbose)
	if endToEndSymKey != "" {
		fmt.Println("End-to-end encryption key:")
		fmt.Println(endToEndSymKey)
	}
	endToEndHmacKey := getValue(db, "endtoendhmackey", "", verbose)
	if endToEndHmacKey != "" {
		fmt.Println(endToEndHmacKey)
	}

}

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

func getYesNo(reader *bufio.Reader, prompt string) bool {
	result := false
	haveResult := false
	for !haveResult {
		fmt.Print(prompt)
		yesno, err := reader.ReadString('\n')
		checkError(err)
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
	return result
}

func getLine(reader *bufio.Reader) string {
	result, err := reader.ReadString('\n')
	checkError(err)
	return trim(result)
}

func doAdminMode(wnet wrpc.IWNetConnection, db *sql.DB, verbose bool) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Admin password: ")
	password := getLine(reader)
	errmsg, err := rpcLogin(wnet, "admin", password)
	if err != nil {
		fmt.Println(err)
		return
	}
	if errmsg != "" {
		fmt.Println(errmsg)
		return
	}
	for {
		fmt.Print("> ")
		command, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("")
				return
			}
		}
		checkError(err)
		command = trim(command)
		params := strings.Split(command, " ")
		if len(params) > 0 {
			switch params[0] {
			case "list":
				if len(params) == 1 {
					fmt.Println("List what?")
					fmt.Println("    users -- list users")
					fmt.Println("    syncpoints -- list sync points")
					fmt.Println("    grants -- list access grants of users to sync points")
				} else {
					switch params[1] {
					case "users":
						errmsg := rpcListUsers(wnet)
						if errmsg != "" {
							fmt.Println(errmsg)
						}
					case "syncpoints":
						server := getValue(db, "server", "", verbose)
						errmsg := rpcListSyncPoints(wnet, server)
						if errmsg != "" {
							fmt.Println(errmsg)
						}
					case "grants":
						errmsg := rpcListGrants(wnet)
						if errmsg != "" {
							fmt.Println(errmsg)
						}
					default:
						fmt.Println("List: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "local":
				if len(params) == 1 {
					fmt.Println("local what?")
					fmt.Println("    show config -- show configuration on local machine")
				} else {
					switch params[1] {
					case "show":
						if len(params) == 2 {
							fmt.Println("local show what?")
							fmt.Println("    config -- show current configuration")
						} else {
							switch params[2] {
							case "config":
								showConfiguration(db, verbose)
							default:
								fmt.Println("local show: " + `"` + params[2] + `"` + " not found.")
							}
						}
					default:
						fmt.Println("local: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "add":
				if len(params) == 1 {
					fmt.Println("Add what?")
					fmt.Println("    user -- add user")
					fmt.Println("    syncpoint -- add sync point on server using absolute path")
					fmt.Println("    grant -- grant a user access to a sync point")
				} else {
					switch params[1] {
					case "user":
						fmt.Print("Email: ")
						email := getLine(reader)
						if verbose {
							fmt.Println("The email you entered is:", email)
						}
						password, errmsg, err := rpcAddUser(wnet, email, roleSyncPointUser)
						if err != nil {
							fmt.Println(err)
							return
						}
						if errmsg != "" {
							if verbose {
								fmt.Println("adduser failed.")
							}
							fmt.Println(errmsg)
						} else {
							fmt.Println("User created. Password is:")
							fmt.Println(password)
							yes := getYesNo(reader, "Set as email and password for this client? (y/n) ")
							if yes {
								setNameValuePair(db, "email", email, verbose, false)
								setNameValuePair(db, "password", password, verbose, false)
							}
						}
					case "syncpoint":
						path := ""
						for path == "" {
							fmt.Print("Path on server: ")
							path = getLine(reader)
						}
						publicid, errmsg, err := rpcAddSyncPoint(wnet, path)
						checkError(err)
						if errmsg != "" {
							if verbose {
								fmt.Println("Could not add sync point.")
							}
							fmt.Println(errmsg)
						} else {
							fmt.Println("The sync point ID is:")
							fmt.Println(publicid)
							yes := getYesNo(reader, "Set key as sync point for current directory tree? (y/n) ")
							if yes {
								setNameValuePair(db, "syncpointid", publicid, verbose, false)
							}
						}
					case "grant":
						email := ""
						for email == "" {
							fmt.Print("Email: ")
							email = getLine(reader)
						}
						syncpublicid := ""
						for syncpublicid == "" {
							fmt.Print("Sync point ID: ")
							syncpublicid = getLine(reader)
						}
						access := 0
						yes := getYesNo(reader, "Grant read access? (y/n) ")
						if yes {
							access |= accessRead
						}
						yes = getYesNo(reader, "Grant write access? (y/n) ")
						if yes {
							access |= accessWrite
						}
						errmsg, err := rpcAddGrant(wnet, email, syncpublicid, access)
						if err != nil {
							fmt.Println(err)
							return
						}
						if errmsg != "" {
							fmt.Println(errmsg)
						}
					default:
						fmt.Println("Add: " + `"` + params[1] + `"` + " not found.")
					}
				}

			case "del":
				if len(params) == 1 {
					fmt.Println("Delete what?")
					fmt.Println("    user -- delete user")
					fmt.Println("    syncpoint -- delete sync point from server")
					fmt.Println("    grant -- revoke a user's access to a sync point")
				} else {
					switch params[1] {
					case "user":
						fmt.Print("Email: ")
						email := getLine(reader)
						if verbose {
							fmt.Println("The email you entered is:", email)
						}
						errmsg, err := rpcDeleteUser(wnet, email)
						if err != nil {
							fmt.Println(err)
							return
						}
						if errmsg != "" {
							if verbose {
								fmt.Println("del user failed.")
							}
							fmt.Println(errmsg)
						}
					case "syncpoint":
						syncpublicid := ""
						for syncpublicid == "" {
							fmt.Print("Sync point ID: ")
							syncpublicid = getLine(reader)
						}
						yes := getYesNo(reader, "Are you sure? Doing this will permanently prevent this server directory from ever being used as a syncpoint in the future. You will need to start with a new blank directory on the server if you want these files synced again. All access grants will be deleted and will need to be set up again if you ever want this sync point back. Are you really sure you want to do this? (y/n) ")
						if yes {
							errmsg, err := rpcDeleteSyncPoint(wnet, syncpublicid)
							if err != nil {
								fmt.Println(err)
								return
							}
							if errmsg != "" {
								if verbose {
									fmt.Println("Could not add sync point.")
								}
								fmt.Println(errmsg)
							}
						}
					case "grant":
						email := ""
						for email == "" {
							fmt.Print("Email: ")
							email = getLine(reader)
						}
						syncpublicid := ""
						for syncpublicid == "" {
							fmt.Print("Sync point ID: ")
							syncpublicid = getLine(reader)
						}
						errmsg, err := rpcDeleteGrant(wnet, email, syncpublicid)
						if err != nil {
							fmt.Println(err)
							return
						}
						if errmsg != "" {
							fmt.Println(errmsg)
						}
					default:
						fmt.Println("Delete: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "help":
				fmt.Println("list")
				fmt.Println("    users -- list users")
				fmt.Println("    syncpoints -- list sync points")
				fmt.Println("    grants -- list access grants of users to sync points")

				fmt.Println("add")
				fmt.Println("    user -- add user")
				fmt.Println("    syncpoint -- add sync point on server using absolute path")
				fmt.Println("    grant -- grant a user access to a sync point")

				fmt.Println("del")
				fmt.Println("    user -- delete user")
				fmt.Println("    syncpoint -- delete sync point from server")
				fmt.Println("    grant -- revoke a user's access to a sync point")

				fmt.Println("local")
				fmt.Println("    show")
				fmt.Println("        config -- show local machine current configuration")
				fmt.Println("help -- this message")
				fmt.Println("quit -- exit program")

				// fmt.Println("== users ==")
				// fmt.Println("listusers -- list users")
				// fmt.Println("adduser -- add user")
				// fmt.Println("== users ==")
				// fmt.Println("listsyncpoints -- list sync points on the server")
				// fmt.Println("addsyncpoint -- create a new sync point on the server")
				// fmt.Println("== access ==")
				// fmt.Println("listgrants -- list access grants")
				// fmt.Println("grantusertosync -- grant access to a user to a sync point on the server")
				// fmt.Println("== other ==")
				// fmt.Println("showconfig -- show current client configuration")

				// fmt.Println("--- the following not implemented yet")
				// fmt.Println("deluser -- delete user")
				// fmt.Println("chuserrole -- change user role")
				// fmt.Println("resetuserpw -- reset user password")
				// fmt.Println("joinsyncpoint -- add current directory to a sync point")
				// fmt.Println("abandonsyncpoint -- remove current dirrectory tree from the sync point")
				// fmt.Println("revokeusertosync -- revoke access from a user from a sync point on the server")

			case "quit":
				return

			default:
				if params[0] != "" {
					fmt.Println("Command " + `"` + params[0] + `"` + " not found.")
				}
			}

		}
	}
}

// ----------------------------------------------------------------
// Code for scanning directory trees and syncing files
// ----------------------------------------------------------------

func isSkippableErrorMessage(message string) bool {
	// if message[len(message)-17:] == "permission denied" {
	//	fmt.Println(message[len(message)-17:])
	//	return true
	// }
	// if message[len(message)-33:] == "operation not supported on socket" {
	//	fmt.Println(message[len(message)-33:])
	//	return true
	// }
	// if message[len(message)-25:] == "no such file or directory" {
	//	fmt.Println(message[len(message)-25:])
	//	return true
	// }
	return false
}

func calcTimeFromNow(someTime int64) string {
	currentTime := time.Now().UnixNano()
	return int64ToStr((currentTime - someTime) / 1000000000)
}

// when we get a tree, we initially set the hash to empty string
// we don't go ahead and compute the hashes because we only compute hashes if the file size or date has changed
// as an optimization
func getDirectoryTree(verbose bool, path string, result []wfileInfo, skipIfPermissionDenied bool) ([]wfileInfo, error) {
	if verbose {
		fmt.Println("Scanning: " + path)
	}
	dir, err := os.Open(makePathSeparatorsForThisOS(path))
	if err != nil {
		if skipIfPermissionDenied {
			if isSkippableErrorMessage(err.Error()) {
				return result, nil
			}
		}
		return result, err
	}
	defer dir.Close()
	filesInDir, err := dir.Readdir(0)
	if err != nil {
		if skipIfPermissionDenied {
			if isSkippableErrorMessage(err.Error()) {
				return result, nil
			}
		}
		return result, err
	}
	for _, filestuff := range filesInDir {
		if filestuff.Name() != "spool" {
			completePath := path + string(os.PathSeparator) + filestuff.Name()
			if filestuff.IsDir() {
				result, err = getDirectoryTree(verbose, completePath, result, skipIfPermissionDenied)
				checkError(err)
			} else {
				if verbose {
					fmt.Println(completePath, "last modified", calcTimeFromNow(filestuff.ModTime().UnixNano()), "seconds ago")
				}
				result = append(result, wfileInfo{completePath, filestuff.Size(), filestuff.ModTime().UnixNano(), ""})
			}
		}
	}
	return result, nil
}

func (ptr *wfileSortSlice) Len() int {
	return len(ptr.theSlice)
}

func (ptr *wfileSortSlice) Less(i, j int) bool {
	return ptr.theSlice[i].filePath < ptr.theSlice[j].filePath
}

func (ptr *wfileSortSlice) Swap(i, j int) {
	filePath := ptr.theSlice[i].filePath
	ptr.theSlice[i].filePath = ptr.theSlice[j].filePath
	ptr.theSlice[j].filePath = filePath
	fileSize := ptr.theSlice[i].fileSize
	ptr.theSlice[i].fileSize = ptr.theSlice[j].fileSize
	ptr.theSlice[j].fileSize = fileSize
	fileTime := ptr.theSlice[i].fileTime
	ptr.theSlice[i].fileTime = ptr.theSlice[j].fileTime
	ptr.theSlice[j].fileTime = fileTime
}

func calcHash(filePath string) string {
	fileHandle, err := os.Open(makePathSeparatorsForThisOS(filePath))
	checkError(err)
	defer fileHandle.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, fileHandle)
	checkError(err)
	encoded := hex.EncodeToString(hash.Sum(nil))
	return encoded
}

func putTreeInTableAndFillInHashesThatNeedToBeUpdated(verbose bool, db *sql.DB, tree []wfileInfo, basePath string, deleteUnused bool) {
	var deleteMap map[int64]bool
	deleteMap = make(map[int64]bool)

	chopOff := len(basePath)

	tx, err := db.Begin()
	checkError(err)

	cmd := "SELECT fileid FROM fileinfo WHERE filehash <> 'deleted';"
	stmtSelExisting, err := tx.Prepare(cmd)
	checkError(err)

	rowsExisting, err := stmtSelExisting.Query()
	checkError(err)
	defer rowsExisting.Close()
	var fileid int64
	fileid = 0
	for rowsExisting.Next() {
		rowsExisting.Scan(&fileid)
		deleteMap[fileid] = true
	}

	cmd = "SELECT fileid, filesize, filetime, filehash FROM fileinfo WHERE filepath = ?;"
	stmtSelCheck, err := tx.Prepare(cmd)
	checkError(err)
	cmd = "UPDATE fileinfo SET filesize = ?, filetime = ?, filehash = ? WHERE fileid = ?;"
	stmtUpd, err := tx.Prepare(cmd)
	checkError(err)
	cmd = "INSERT INTO fileinfo (filepath, filesize, filetime, filehash) VALUES (?, ?, ?, ?);"
	stmtIns, err := tx.Prepare(cmd)
	checkError(err)
	cmd = "UPDATE fileinfo SET filehash = 'deleted', filetime = ? WHERE fileid = ?;"
	stmtUpMarkDel, err := tx.Prepare(cmd)
	checkError(err)

	var filesize int64
	var filetime int64
	var oldFileHash string
	ltr := len(tree)
	for ii := 0; ii < ltr; ii++ {
		filterOutCheck := tree[ii].filePath[chopOff+1:]
		if (filterOutCheck != databaseFileName) && (filterOutCheck != tempFileName) {
			if verbose {
				fmt.Print(tree[ii].filePath[chopOff:])
			}
			rowsCheck, err := stmtSelCheck.Query(tree[ii].filePath[chopOff:])
			checkError(err)
			defer rowsCheck.Close()
			var fileid int64
			fileid = 0
			for rowsCheck.Next() {
				rowsCheck.Scan(&fileid, &filesize, &filetime, &oldFileHash)
			}
			if fileid == 0 {
				fileHash := calcHash(tree[ii].filePath)
				if verbose {
					fmt.Println(" - NEW, original hash is:", fileHash)
				}
				tree[ii].fileHash = fileHash
				_, err := stmtIns.Exec(makePathSeparatorsStandard(tree[ii].filePath[chopOff:]), tree[ii].fileSize, tree[ii].fileTime, fileHash)
				checkError(err)
			} else {
				if (filesize == tree[ii].fileSize) && (filetime == tree[ii].fileTime) {
					// assume hasn't changed -- leave alone!
					if verbose {
						fmt.Println(" - Has not changed")
					}
					tree[ii].fileHash = oldFileHash
				} else {
					fileHash := calcHash(tree[ii].filePath)
					if verbose {
						fmt.Println(" - CHANGED, new hash:", fileHash)
					}
					tree[ii].fileHash = fileHash
					_, err := stmtUpd.Exec(tree[ii].fileSize, tree[ii].fileTime, fileHash, fileid)
					checkError(err)
				}
				delete(deleteMap, fileid)
			}
		}
	}
	for fileid, _ = range deleteMap {
		if verbose {
			fmt.Println("marking file ID", fileid, "as deleted.")
		}
		currentTime := time.Now().UnixNano()
		fmt.Println("fileid", fileid, "currentTime", currentTime)
		_, err := stmtUpMarkDel.Exec(currentTime, fileid)
		checkError(err)
	}
	err = tx.Commit()
	checkError(err)
}

func retrieveTreeFromDB(verbose bool, db *sql.DB) []wfileInfo {
	tx, err := db.Begin()
	checkError(err)

	result := make([]wfileInfo, 0)

	cmd := "SELECT fileid, filepath, filesize, filetime, filehash FROM fileinfo WHERE 1 ORDER BY filepath;"
	stmtSel, err := tx.Prepare(cmd)
	checkError(err)

	rows, err := stmtSel.Query()
	checkError(err)
	defer rows.Close()

	var fileid int64
	var filepath string
	var filesize int64
	var filetime int64
	var filehash string
	for rows.Next() {
		rows.Scan(&fileid, &filepath, &filesize, &filetime, &filehash)
		result = append(result, wfileInfo{filepath, filesize, filetime, filehash})
	}

	err = tx.Commit()
	checkError(err)

	return result
}

func synchronizeTrees(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, syncpublicid string, localPath string, localTree []wfileInfo, remotePath string, remoteTree []wfileInfo, serverTimeOffset int64) {
	filterDatabaseFile := "/" + databaseFileName
	filterTempFile := "/" + tempFileName
	localIdx := 0
	remoteIdx := 0
	for (localIdx < len(localTree)) || (remoteIdx < len(remoteTree)) {
		toUploadLocal := -1    // -1 is used as a magic value to indicate not to copy
		toDownloadRemote := -1 // -1 is used as a magic value to indicate not to copy
		toDeleteRemote := -1   // -1 is used as a magic value to indicate not to delete
		toDeleteLocal := -1    // -1 is used as a magic value to indicate not to delete
		if localIdx == len(localTree) {
			if verbose {
				fmt.Println("Off end of local tree")
			}
			toDownloadRemote = remoteIdx
			remoteIdx++
		} else {
			localCompare := localTree[localIdx].filePath
			if remoteIdx == len(remoteTree) {
				if verbose {
					fmt.Println("Off end of remote tree")
				}
				toUploadLocal = localIdx
				localIdx++
			} else {
				remoteCompare := remoteTree[remoteIdx].filePath
				if verbose {
					fmt.Println("Comparing", localCompare, "with", remoteCompare)
				}
				if localCompare == remoteCompare {
					if verbose {
						fmt.Println("Same file -- comparing file hashes.")
					}
					if localTree[localIdx].fileHash != remoteTree[remoteIdx].fileHash {
						if verbose {
							fmt.Println("File hashes are different -- determining which is newer.")
							fmt.Println(" Local file time is:", localTree[localIdx].fileTime)
							fmt.Println("Remote file time is:", remoteTree[remoteIdx].fileTime)
						}
						if localTree[localIdx].fileTime > remoteTree[remoteIdx].fileTime {
							if localTree[localIdx].fileHash == "deleted" {
								toDeleteRemote = remoteIdx
								if verbose {
									fmt.Println("Local file is newer and deleted-- marked remote file to be deleted")
								}
							} else {
								toUploadLocal = localIdx
								if verbose {
									fmt.Println("Local file is newer -- marked to upload")
								}
							}
						} else {
							if remoteTree[remoteIdx].fileHash == "deleted" {
								toDeleteLocal = localIdx
								if verbose {
									fmt.Println("Remote file is newer and deleted -- marked local file to be deleted")
								}
							} else {
								toDownloadRemote = remoteIdx
								if verbose {
									fmt.Println("Remote file is newer -- marked to download")
								}
							}
						}
					}
					localIdx++
					remoteIdx++
				} else {
					if verbose {
						fmt.Println("Different files -- figure out which is first in alphabetical order.")
					}
					if localCompare < remoteCompare {
						if verbose {
							fmt.Println("Files are different, local is first -- marked to upload")
						}
						toUploadLocal = localIdx
						localIdx++
					} else {
						if verbose {
							fmt.Println("Files are different, remote is first -- marked to download")
						}
						toDownloadRemote = remoteIdx
						remoteIdx++
					}
				}
			}
		}
		if toUploadLocal >= 0 {
			if (localTree[toUploadLocal].filePath != filterDatabaseFile) && (localTree[toUploadLocal].filePath != filterTempFile) { // filter out ourselves
				fmt.Println("Pushing:", localTree[toUploadLocal].filePath)
				localfilepath := localPath + localTree[toUploadLocal].filePath
				filehash := localTree[toUploadLocal].fileHash
				errmsg := sendFile(wnet, syncpublicid, localPath, localfilepath, filehash, serverTimeOffset)
				if errmsg != "ReceptionComplete" {
					fmt.Println(errmsg)
				}
			}
		}
		if toDownloadRemote >= 0 {
			if (remoteTree[toDownloadRemote].filePath != filterDatabaseFile) && (remoteTree[toDownloadRemote].filePath != filterTempFile) { // filter out ourselves
				fmt.Println("Pulling:", remoteTree[toDownloadRemote].filePath)
				localfilepath := localPath + remoteTree[toDownloadRemote].filePath
				filehash := remoteTree[toDownloadRemote].fileHash
				errmsg := retrieveFile(verbose, db, wnet, syncpublicid, localPath, localfilepath, filehash, serverTimeOffset)
				if errmsg != "" {
					fmt.Println(errmsg)
					panic(errmsg)
				}
			}
		}
		if toDeleteRemote >= 0 {
			if (remoteTree[toDeleteRemote].filePath != filterDatabaseFile) && (remoteTree[toDeleteRemote].filePath != filterTempFile) { // filter out ourselves
				fmt.Println("Pushing delete notification: ", remoteTree[toDeleteRemote].filePath)
				remotefilepath := remoteTree[toDeleteRemote].filePath
				filehash := remoteTree[toDeleteRemote].fileHash
				errmsg, err := rpcMarkFileDeleted(wnet, syncpublicid, remotefilepath, filehash)
				if err != nil {
					fmt.Println(err.Error())
					panic(err)
				}
				if errmsg != "" {
					fmt.Println(errmsg)
					panic(errmsg)
				}
			}
		}
		if toDeleteLocal >= 0 {
			if (localTree[toDeleteLocal].filePath != filterDatabaseFile) && (localTree[toDeleteLocal].filePath != filterTempFile) { // filter out ourselves
				fmt.Println("Deleting: ", localTree[toDeleteLocal].filePath)
				localfilepath := localPath + makePathSeparatorsForThisOS(localTree[toDeleteLocal].filePath)
				fmt.Println("localfilepath", localfilepath)
				os.Remove(localfilepath)
			}
		}
	}
}

func dumpTree(tree []wfileInfo) {
	for _, fileinfo := range tree {
		fmt.Println(fileinfo.filePath)
	}
}

func main() {
	currentPath, err := os.Getwd()
	checkError(err)
	vflag := flag.Bool("v", false, "verbose")
	cflag := flag.Bool("c", false, "configure")
	iflag := flag.Bool("i", false, "initialize")
	fflag := flag.String("f", "", "use specified file")
	jflag := flag.Bool("j", false, "import server key")
	kflag := flag.Bool("k", false, "show server key")
	sflag := flag.Bool("s", false, "show configuration")
	aflag := flag.Bool("a", false, "admin mode")
	gflag := flag.Bool("g", false, "generate end-to-end encryption key")
	eflag := flag.Bool("e", false, "import end-to-end encryption key")
	xflag := flag.Bool("x", false, "show end-to-end encryption key")
	flag.Parse()
	verbose := *vflag
	configure := *cflag
	initialize := *iflag
	useFile := *fflag
	importServerKeys := *jflag
	showServerKeys := *kflag
	showConfig := *sflag
	adminMode := *aflag
	generateEndToEndKeys := *gflag
	importEndToEndKeys := *eflag
	showEndToEndKeys := *xflag
	if verbose {
		fmt.Println("Command line flags:")
		fmt.Println("    Initialize mode:", onOff(initialize))
		fmt.Println("    Configure mode:", onOff(configure))
		fmt.Println("    Import server key mode:", onOff(importServerKeys))
		fmt.Println("    Show server key:", onOff(showServerKeys))
		fmt.Println("    Admin mode:", onOff(adminMode))
		fmt.Println("    Use database file (manual override):", useFile)
		fmt.Println("    Generate End-To-End encryption keys:", onOff(generateEndToEndKeys))
	}
	rootPath := ""
	var db *sql.DB
	if initialize {
		if verbose {
			fmt.Println("Creating state file in current directory.")
		}
		db, err = sql.Open("sqlite3", currentPath+string(os.PathSeparator)+databaseFileName)
		checkError(err)
		initializeDatabase(db)
		fmt.Println("Initialized.")
		db.Close()
		return
	} else {
		rootPath, db, err = getStateDB(currentPath, useFile, databaseFileName, verbose)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	defer db.Close()
	if importServerKeys {
		var symKeyStr string
		var hmacKeyStr string
		fmt.Scanln(&symKeyStr)
		symkey, err := hex.DecodeString(symKeyStr)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Scanln(&hmacKeyStr)
		hmackey, err := hex.DecodeString(hmacKeyStr)
		if err != nil {
			fmt.Println(err)
			return
		}
		setNameValuePair(db, "serversymkey", hex.EncodeToString(symkey), verbose, false)
		setNameValuePair(db, "serverhmackey", hex.EncodeToString(hmackey), verbose, false)
		return
	}
	if showServerKeys {
		symmetricKeyStr := getValue(db, "serversymkey", "", verbose)
		hmacKeyStr := getValue(db, "serverhmackey", "", verbose)
		fmt.Println(symmetricKeyStr)
		fmt.Println(hmacKeyStr)
		return
	}
	if configure {
		server := ""
		for server == "" {
			fmt.Print("Server: ")
			fmt.Scanln(&server)
		}
		setNameValuePair(db, "server", server, verbose, false)
		port := 0
		for port == 0 {
			var ptStr string
			fmt.Print("Port: ")
			fmt.Scanln(&ptStr)
			port = strToInt(ptStr)
		}
		setNameValuePair(db, "port", intToStr(port), verbose, false)
		email := ""
		fmt.Print("Email: ")
		fmt.Scanln(&email)
		setNameValuePair(db, "email", email, verbose, false)
		password := ""
		fmt.Print("Password: ")
		fmt.Scanln(&password)
		setNameValuePair(db, "password", password, verbose, false)
		syncPointID := ""
		fmt.Print("Sync point ID: ")
		fmt.Scanln(&syncPointID)
		setNameValuePair(db, "syncpointid", syncPointID, verbose, false)
		return
	}
	if showConfig {
		showConfiguration(db, verbose)
		return
	}
	if generateEndToEndKeys {
		endToEndSymBin, err := generateAESKey()
		checkError(err)
		endToEndSymKey := hex.EncodeToString(endToEndSymBin)
		endToEndHmacBin, err := generateAESKey()
		checkError(err)
		endToEndHmacKey := hex.EncodeToString(endToEndHmacBin)
		setNameValuePair(db, "endtoendsymkey", endToEndSymKey, verbose, false)
		setNameValuePair(db, "endtoendhmackey", endToEndHmacKey, verbose, false)
		fmt.Println(endToEndSymKey)
		fmt.Println(endToEndHmacKey)
		return
	}
	if importEndToEndKeys {
		var endToEndSymStr string
		var endToEndHmacStr string
		fmt.Scanln(&endToEndSymStr)
		endToEndSymKey, err := hex.DecodeString(endToEndSymStr)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Scanln(&endToEndHmacStr)
		endToEndHmacKey, err := hex.DecodeString(endToEndHmacStr)
		if err != nil {
			fmt.Println(err)
			return
		}
		setNameValuePair(db, "endtoendsymkey", hex.EncodeToString(endToEndSymKey), verbose, false)
		setNameValuePair(db, "endtoendhmackey", hex.EncodeToString(endToEndHmacKey), verbose, false)
		return
	}
	if showEndToEndKeys {
		endToEndSymKeyStr := getValue(db, "endtoendsymkey", "", verbose)
		endToEndHmacKeyStr := getValue(db, "endtoendhmackey", "", verbose)
		fmt.Println(endToEndSymKeyStr)
		fmt.Println(endToEndHmacKeyStr)
		return
	}
	//
	// ok, if we got here, we're not doing configuration! We're
	// transferring files!!
	// Brrrp! Unless we're going into Admin Mode
	server := getValue(db, "server", "", verbose)
	if verbose {
		fmt.Println("Server:", server)
	}
	ptStr := getValue(db, "port", "0", verbose)
	port := strToInt(ptStr)
	if verbose {
		fmt.Println("Port:", port)
	}
	email := getValue(db, "email", "", verbose)
	if verbose {
		fmt.Println("Email:", email)
	}
	password := getValue(db, "password", "", false)
	if verbose {
		fmt.Println("Password:", password)
	}
	syncPointID := getValue(db, "syncpointid", "", verbose)
	if verbose {
		fmt.Println("Sync point ID:", syncPointID)
	}
	endToEndSymKey := getValue(db, "endtoendsymkey", "", verbose)
	if verbose {
		fmt.Println("End-to-end symmetric key:", endToEndSymKey)
	}
	endToEndHmacKey := getValue(db, "endtoendhmackey", "", verbose)
	if verbose {
		fmt.Println("End-to-end keyed-hash message authentication code key:", endToEndHmacKey)
	}
	if (server == "") || (port == 0) || (email == "") || (password == "") || (syncPointID == "") {
		fmt.Println("Server and sync point information is not set up.")
		fmt.Println("Use same -c to configure.")
		fmt.Println("Use same -l to list current configuration.")
		return
	}
	serverSymKeyStr := getValue(db, "serversymkey", "", verbose)
	serverSymKey, err := hex.DecodeString(serverSymKeyStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	serverHmacKeyStr := getValue(db, "serverhmackey", "", verbose)
	serverHmacKey, err := hex.DecodeString(serverHmacKeyStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	if (len(serverSymKey) == 0) || (len(serverHmacKey) == 0) {
		fmt.Println("Server key is not set up.")
		fmt.Println("Use same -k on the server to export the key.")
		fmt.Println("Use same -j to import them here.")
		fmt.Println("Use same -k here to show the server key set here.")
		return
	}
	wnet, err := openConnection(serverSymKey, serverHmacKey, server, port)
	defer wnet.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	if verbose {
		fmt.Println("Connected to server.")
	}
	if adminMode {
		doAdminMode(wnet, db, verbose)
		return
	}
	localTime1 := getLocalTime()
	var remoteTime int64
	remoteTime, err = rpcGetTime(wnet)
	if err != nil {
		fmt.Println(err)
		return
	}
	localTime2 := getLocalTime()
	serverTimeOffset := remoteTime - (localTime1 + ((localTime2 - localTime1) >> 1))
	if verbose {
		fmt.Println("Difference between server time and local time:", serverTimeOffset, "nanoseconds")
	}
	// sendFile("/Users/waynerad/Documents/flushdns.txt", wnet, serverTimeOffset)
	errmsg, err := rpcLogin(wnet, email, password)
	if err != nil {
		fmt.Println("Login failed:", err)
	}
	if errmsg != "" {
		fmt.Println("Login failed:", errmsg)
		return
	}
	if verbose {
		fmt.Println("Log in as", email, "successful")
		fmt.Println("Scanning local disk")
	}
	// Ok, now that we're logged in, let's scan the local disk and ask the remote server to tell us what it has
	var sortSlice wfileSortSlice
	localTree := make([]wfileInfo, 0)
	path := currentPath
	if verbose {
		fmt.Println("Scanning local tree.")
	}
	localTree, err = getDirectoryTree(verbose, path, localTree, false)
	checkError(err)
	sortSlice.theSlice = localTree
	sort.Sort(&sortSlice)
	basePath := rootPath // redundant copy
	if verbose {
		fmt.Println("base path:", basePath)
	}
	if verbose {
		fmt.Println("Calculating file hashes")
	}
	putTreeInTableAndFillInHashesThatNeedToBeUpdated(verbose, db, localTree, basePath, true)
	// At this point, we have to throw away our tree and get a new
	// one from the DB because otherwise we have a tree without
	// deleted files. We have to track the deleted files because
	// otherwise when a user deletes a file, it will just magically
	// reappear every time
	localTree = retrieveTreeFromDB(verbose, db)
	remoteTree, err := rpcGetServerTreeForSyncPoint(wnet, syncPointID)
	if err != nil {
		fmt.Println(err)
		return
	}
	// sortSlice.theSlice = remoteTree
	// sort.Sort(&sortSlice) -- DB query on remote end should sort
	synchronizeTrees(verbose, db, wnet, syncPointID, path, localTree, "", remoteTree, serverTimeOffset)
	// time.Sleep(time.Second)
}
