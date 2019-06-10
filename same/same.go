package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"hash"
	"io"
	"os"
	"samecommon"
	"sort"
	"strconv"
	"strings"
	"time"
	"wrpc"
)

type fileSortSlice struct {
	theSlice []samecommon.SameFileInfo
}

const databaseFileName = ".samestate"
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

func getLocalTime() int64 {
	now := time.Now()
	result := now.UnixNano()
	return result
}

func openConnection(symmetricKey []byte, hmacKey []byte, remoteHost string, portNumber int) (wrpc.IWNetConnection, error) {
	wnet := wrpc.NewConnection()
	wnet.SetDest(remoteHost, portNumber)
	wnet.SetKeys(symmetricKey, hmacKey)
	err := wnet.Open()
	return wnet, err
}

func stashFileInfo(db *sql.DB, filepath string, filesize int64, filetime int64, filehash string) error {
	filepath = samecommon.MakePathSeparatorsStandard(filepath)
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

func encryptDirectoryPath(filepath string, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) (string, error) {
	// This function unfortunately blows up short names because it tacks a
	// digital signature to the end, and then it hex encodes the whole
	// thing, so filename length + 32 all times 2.
	ciphertext := make([]byte, 4096)
	pieces := strings.Split(filepath, "/")
	lnp := len(pieces)
	result := ""
	for ii := 1; ii < lnp; ii++ {
		block, err := aes.NewCipher(endToEndSymmetricKey)
		if err != nil {
			return "", err
		}
		dirCipher := cipher.NewOFB(block, endToEndIV)
		plaintext := []byte(pieces[ii])
		nn := len(plaintext)
		dirCipher.XORKeyStream(ciphertext[:nn], plaintext)
		dirHasher := hmac.New(sha256.New, endToEndHmacKey)
		dirHasher.Write(ciphertext[:nn])
		signature := dirHasher.Sum(nil)
		result += "/" + hex.EncodeToString(ciphertext[:nn]) + hex.EncodeToString(signature)
	}
	return result, nil
}

func decryptDirectoryPath(filepath string, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) (string, error) {
	plaintext := make([]byte, 4096)
	pieces := strings.Split(filepath, "/")
	lnp := len(pieces)
	result := ""
	for ii := 1; ii < lnp; ii++ {
		ciphertext, err := hex.DecodeString(pieces[ii])
		if err != nil {
			return "", err
		}
		block, err := aes.NewCipher(endToEndSymmetricKey)
		if err != nil {
			return "", err
		}
		cipher := cipher.NewOFB(block, endToEndIV)
		// cipher set up
		nn := len(ciphertext) - 32
		dirHasher := hmac.New(sha256.New, endToEndHmacKey)
		dirHasher.Write(ciphertext[:nn])
		cipher.XORKeyStream(plaintext[:nn], ciphertext[:nn])
		expectedMAC := dirHasher.Sum(nil)
		match := hmac.Equal(ciphertext[len(ciphertext)-32:], expectedMAC)
		if !match {
			return "", errors.New("decryptDirectoryPath: directory HMAC signature check failed.")
		}
		result += "/" + string(plaintext[:nn])
	}
	return result, nil
}

func printPercent(bytesread int64, filesize int64, previous string, prec int) (string, int) {
	// Had to modify this to expand the precision when the same percentage
	// is repeated so user can get meaningful feedback on very large files.
	pct := strconv.FormatFloat((float64(bytesread)/float64(filesize))*100, 'f', prec, 64) + "%"
	if pct == previous {
		prec++
		pct = strconv.FormatFloat((float64(bytesread)/float64(filesize))*100, 'f', prec, 64) + "%"
	}
	fmt.Println(pct)
	return pct, prec
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
	result, err := wrpc.StandardIntReply(wnet, "GetTime")
	return result, err
}

func rpcLogin(wnet wrpc.IWNetConnection, username string, password string) error {
	if len(password) != 80 {
		return errors.New("Password is wrong length. Check password and make sure password is valid.")
	}
	passwordBin := make([]byte, 64)
	ndst, _, err := ascii85.Decode(passwordBin, []byte(password), true)
	if err != nil {
		return err
	}
	if ndst != 64 {
		return errors.New("Password is of wrong length.")
	}
	if len(passwordBin) != 64 {
		panic("Decoded password is wrong length.")
	}
	if wnet == nil {
		return errors.New("Cannot login: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("Login", 0, 1)
	rpc.StartTable("", 2, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColByteArray)
	rpc.StartRow()
	rpc.AddRowColumnString(username)
	rpc.AddRowColumnByteArray(passwordBin[:32])
	err = rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	rplmsg, err := wnet.NextMessage()
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		panic("Connection closed by same server.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	if reply.GetDBName() == "LoginReply" {
		// if we're here, and didn't get the challenge, it must be
		// because the login has failed already
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			return err
		}
		return errors.New(errmsg)
	}
	if reply.GetDBName() != "Challenge" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			return err
		}
		return errors.New(reply.GetDBName() + ": " + errmsg)
	}
	challengeBin, err := reply.GetByteArray(0, 0, 0)
	if err != nil {
		return err
	}
	combo := append(passwordBin[32:], challengeBin...) // destroys passwordBin, good thing we don't need it in the rest of this function
	sum := sha256.Sum256(combo)
	response := make([]byte, 32)
	// copy(response,sum) -- gives error second argument to copy should be slice or string; have [32]byte
	for ii := 0; ii < 32; ii++ {
		response[ii] = sum[ii]
	}
	// send response back
	rpc = wrpc.NewDB()
	rpc.StartDB("Response", 0, 1)
	rpc.StartTable("", 1, 1)
	rpc.AddColumn("", wrpc.ColByteArray)
	rpc.StartRow()
	rpc.AddRowColumnByteArray(response)
	err = rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "Login")
	return err
}

func rpcListUsers(wnet wrpc.IWNetConnection) error {
	if wnet == nil {
		return errors.New("Cannot list users: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("ListUsers", 0, 0)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	reply, err := wrpc.StandardReply(wnet, "ListUsers")
	if err != nil {
		return err
	}
	num := reply.GetNumRows(0)
	for ii := 0; ii < num; ii++ {
		username, err := reply.GetString(0, ii, 0)
		if err != nil {
			return err
		}
		role64, err := reply.GetInt(0, ii, 1)
		if err != nil {
			return err
		}
		role := int(role64)
		fmt.Println(username, "-", samecommon.RoleFlagsToString(role))
	}
	errmsg, err := reply.GetString(1, 0, 0)
	if err != nil {
		return err
	}
	if errmsg != "" {
		return errors.New(errmsg)
	}
	return nil
}

func rpcAddUser(wnet wrpc.IWNetConnection, username string, role int) (string, error) {
	if wnet == nil {
		return "", errors.New("Cannot add user: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("AddUser", 0, 1)
	rpc.StartTable("", 2, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColInt)
	rpc.StartRow()
	rpc.AddRowColumnString(username)
	rpc.AddRowColumnInt(int64(role))
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	reply, err := wrpc.StandardReply(wnet, "AddUser")
	if err != nil {
		return "", err
	}
	passwordBin, err := reply.GetByteArray(0, 0, 0)
	if err != nil {
		return "", err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return "", err
	}
	if errmsg != "" {
		return "", errors.New(errmsg)
	}
	passwordStr := make([]byte, 86)
	num := ascii85.Encode(passwordStr, passwordBin)
	return string(passwordStr[:num]), nil
}

func rpcAddSyncPoint(wnet wrpc.IWNetConnection, path string) (string, error) {
	if wnet == nil {
		return "", errors.New("Cannot add sync point: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("AddSyncPoint", 0, 1)
	rpc.StartTable("", 0, 0)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(path)
	rpc.SendDB(wnet)
	reply, err := wrpc.StandardReply(wnet, "AddSyncPoint")
	if err != nil {
		return "", err
	}
	publicid, err := reply.GetString(0, 0, 0)
	if err != nil {
		return "", err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return publicid, err
	}
	if errmsg != "" {
		return publicid, errors.New(errmsg)
	}
	return publicid, nil
}

func rpcListSyncPoints(wnet wrpc.IWNetConnection, server string) error {
	if wnet == nil {
		return errors.New("Cannot list sync points: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("ListSyncPoints", 0, 0)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	reply, err := wrpc.StandardReply(wnet, "ListSyncPoints")
	if err != nil {
		return err
	}
	num := reply.GetNumRows(0)
	for ii := 0; ii < num; ii++ {
		publicid, err := reply.GetString(0, ii, 0)
		if err != nil {
			return err
		}
		path, err := reply.GetString(0, ii, 1)
		if err != nil {
			return err
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
		return err
	}
	if errmsg != "" {
		return errors.New(errmsg)
	}
	return nil
}

func rpcAddGrant(wnet wrpc.IWNetConnection, username string, syncpublicid string, access int) error {
	if wnet == nil {
		return errors.New("Cannot add grant: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("AddGrant", 0, 1)
	rpc.StartTable("", 0, 0)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColInt)
	rpc.StartRow()
	rpc.AddRowColumnString(username)
	rpc.AddRowColumnString(syncpublicid)
	rpc.AddRowColumnInt(int64(access))
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "AddGrant")
	return err
}

func rpcListGrants(wnet wrpc.IWNetConnection) error {
	if wnet == nil {
		return errors.New("Cannot list grants: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("ListGrants", 0, 0)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	reply, err := wrpc.StandardReply(wnet, "ListGrants")
	if err != nil {
		return err
	}
	num := reply.GetNumRows(0)
	for ii := 0; ii < num; ii++ {
		username, err := reply.GetString(0, ii, 0)
		if err != nil {
			return err
		}
		publicid, err := reply.GetString(0, ii, 1)
		if err != nil {
			return err
		}
		access64, err := reply.GetInt(0, ii, 2)
		if err != nil {
			return err
		}
		access := int(access64)
		fmt.Println(username, "-> has access to sync point ->", publicid, "-> with permissions:", samecommon.AccessFlagsToString(access))
	}
	errmsg, err := reply.GetString(1, 0, 0)
	if err != nil {
		return err
	}
	if errmsg != "" {
		return errors.New(errmsg)
	}
	return nil
}

func rpcDeleteUser(wnet wrpc.IWNetConnection, username string) error {
	if wnet == nil {
		return errors.New("Cannot delete user: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("DeleteUser", 0, 1)
	rpc.StartTable("", 1, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(username)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "DeleteUser")
	return err
}

func rpcDeleteSyncPoint(wnet wrpc.IWNetConnection, path string) error {
	if wnet == nil {
		return errors.New("Cannot delete sync point: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("DeleteSyncPoint", 0, 1)
	rpc.StartTable("", 1, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(path)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "DeleteSyncPoint")
	return err
}

func rpcDeleteGrant(wnet wrpc.IWNetConnection, username string, syncpublicid string) error {
	if wnet == nil {
		return errors.New("Cannot delete grant: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("DeleteGrant", 0, 1)
	rpc.StartTable("", 2, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(username)
	rpc.AddRowColumnString(syncpublicid)
	err := rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "DeleteGrant")
	return err
}

func rpcGetServerTreeForSyncPoint(wnet wrpc.IWNetConnection, syncpublicid string) ([]samecommon.SameFileInfo, error) {
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
	reply, err := wrpc.StandardReply(wnet, "GetServerTreeForSyncPoint")
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
	result := make([]samecommon.SameFileInfo, 0)
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
		reup, err := reply.GetBool(0, ii, 3)
		if err != nil {
			return nil, err
		}
		result = append(result, samecommon.SameFileInfo{filepath, 0, filetime, filehash, reup})
	}
	return result, nil
}

func sendFile(verbose bool, wnet wrpc.IWNetConnection, syncpublicid string, localdir string, localfilepath string, filehash string, serverTimeOffset int64, endToEndEncryption bool, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) error {
	info, err := os.Stat(localfilepath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return errors.New("CANNOT_STAT")
		// return err
	}
	if info.IsDir() {
		fmt.Println("localfilepath", localfilepath)
		fmt.Println("info", info)
		return errors.New("File given to transfer is a directory")
	}
	//
	// Step 1: Call ReceiveFile API on remote server, tell them the
	// name of the file we're going to send and how big it is
	//
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
	if endToEndEncryption {
		remotefilepath, err = encryptDirectoryPath(remotefilepath, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
		if err != nil {
			return err
		}
	}
	modtime := info.ModTime().UnixNano() + serverTimeOffset
	filesize := info.Size()
	if endToEndEncryption {
		filesize += aes.BlockSize + 32
	}
	//
	msg.StartRow()
	msg.AddRowColumnString(syncpublicid)
	msg.AddRowColumnString(remotefilepath)
	msg.AddRowColumnInt(filesize)
	msg.AddRowColumnInt(modtime)
	msg.AddRowColumnString(filehash)
	msg.SendDB(wnet)
	//
	// Step 2: Get a reply back saying "Go Ahead"
	// If we don't get the "Go Ahead And Send", we don't send the file
	//
	rplmsg, err := wnet.NextMessage()
	if len(rplmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		return errors.New("Connection closed by same server.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(rplmsg)
	if reply.GetDBName() != "ReceiveFileReply" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			return err
		}
		return errors.New(reply.GetDBName() + ": " + errmsg)
	}
	result, err := reply.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	errmsg, err := reply.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	if result != "GoAheadAndSend" {
		return errors.New(errmsg)
	}
	//
	// Step 3: Actually send the file
	// For this we send the bytes in "shove" mode, instead of using the Mini-DB RPC system
	// It's gets pushed through the crypto system, so don't worry,
	// the bits on the wire are still encrypted
	//
	const bufferSize = 32768
	buffer := make([]byte, bufferSize)
	var endToEndIvOutgoing []byte
	var endToEndIvSent bool
	var endToEndCipherstreamOut cipher.Stream
	var endToEndBuffer []byte
	var endToEndHasher hash.Hash
	if endToEndEncryption {
		if verbose {
			fmt.Println("End-to-end encryption is enabled: transmitting file with end-to-end encryption")
		}
		endToEndBuffer = make([]byte, bufferSize+aes.BlockSize)
		// Setup here is the same as in wnet.SetKeys
		// endToEndSymmetricKey = symmetricKey
		// endToEndHmacKey = hmacKey
		block, err := aes.NewCipher(endToEndSymmetricKey)
		if err != nil {
			return err
		}
		endToEndIvOutgoing = make([]byte, aes.BlockSize)
		_, err = rand.Read(endToEndIvOutgoing)
		if err != nil {
			return err
		}
		endToEndIvSent = false
		endToEndCipherstreamOut = cipher.NewOFB(block, endToEndIvOutgoing)
	}
	ciphertext := make([]byte, bufferSize+aes.BlockSize) // allocated here as a memory management optimization
	//
	fh, err := os.Open(samecommon.MakePathSeparatorsForThisOS(localfilepath))
	if err != nil {
		return err
	}
	keepGoing := true
	thresholdTime := getLocalTime() + 1000000000
	var bytesread int64
	bytesread = 0
	previous := ""
	prec := 0
	for keepGoing {
		currentTime := getLocalTime()
		if currentTime > thresholdTime {
			previous, prec = printPercent(bytesread, filesize, previous, prec)
			thresholdTime = currentTime + 1000000000
		}
		n, err := fh.Read(buffer)
		if err == nil {
			bytesread += int64(n)
			if endToEndEncryption {
				if endToEndIvSent {
					endToEndCipherstreamOut.XORKeyStream(endToEndBuffer[:n], buffer[:n])
					err = wnet.ShoveBytes(endToEndBuffer[:n], ciphertext[:n])
					if err != nil {
						return err
					}
					endToEndHasher.Write(endToEndBuffer[:n])
				} else {

					// Yes, we make the file size 16 bytes larger.
					// (Actually 48 when you include the HMAC signature.)
					// The server won't know.
					offset := copy(endToEndBuffer, endToEndIvOutgoing)
					endToEndCipherstreamOut.XORKeyStream(endToEndBuffer[offset:offset+n], buffer[:n])
					offset += n
					err = wnet.ShoveBytes(endToEndBuffer[:offset], ciphertext[:offset])
					if err != nil {
						return err
					}
					endToEndHasher = hmac.New(sha256.New, endToEndHmacKey)
					endToEndHasher.Write(endToEndBuffer[:offset])
					endToEndIvSent = true

				}
			} else {
				err = wnet.ShoveBytes(buffer[:n], ciphertext[:n])
				if err != nil {
					return err
				}
			}
			if err != nil {
				return err
			}
		} else {
			if err == io.EOF {
				keepGoing = false
			} else {
				return err
			}
		}
	}
	fh.Close()
	if endToEndEncryption {
		if !endToEndIvSent {
			// If this happens, it means we have a 0-byte file. We
			// could do a call to to ShoveBytes just for the IV
			// before we start sending the file, but that would
			// cause an unnecessary packet round-trip across the
			// network just for the IV for every file, and that's
			// not an efficient way to do it because the vast
			// majority of files are not 0-byte files. So we
			// duplicate some code here to special-case the 0-byte
			// files.
			offset := copy(endToEndBuffer, endToEndIvOutgoing)
			err = wnet.ShoveBytes(endToEndBuffer[:offset], ciphertext[:offset])
			if err != nil {
				return err
			}
			endToEndHasher = hmac.New(sha256.New, endToEndHmacKey)
			endToEndHasher.Write(endToEndBuffer[:offset])
			endToEndIvSent = true
		}
		signature := endToEndHasher.Sum(nil)
		err = wnet.ShoveBytes(signature, ciphertext[:len(signature)])
	}
	//
	// Step 4: Get reply from the remote end that the bytes were
	// received and the signature checked out
	//
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
		return err
	}
	errmsg, err = reply.GetString(0, 0, 1)
	if err != nil {
		return err
	}
	if errmsg != "" {
		return errors.New(errmsg)
	}
	if result != "ReceptionComplete" {
		return errors.New(result)
	}
	return nil
}

func retrieveFile(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, syncpublicid string, localdir string, localfilepath string, filehash string, serverTimeOffset int64, endToEndEncryption bool, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) error {
	if verbose {
		fmt.Println("Seeking to update file:", localfilepath)
		fmt.Println("    with file hash:", filehash)
	}
	version := 0

	remotefilepath := localfilepath[len(localdir):]
	if verbose {
		fmt.Println("    Requesting retrieval of:", remotefilepath)
	}
	var err error
	if endToEndEncryption {
		remotefilepath, err = encryptDirectoryPath(remotefilepath, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
		if err != nil {
			return err
		}
	}
	//
	// Step 1: Call SendFile API on remote server, tell them the
	// name of the file we want
	//
	msg := wrpc.NewDB()
	msg.StartDB("SendFile", 0, 1)
	msg.StartTable("", 3, 1)
	msg.AddColumn("syncpublicid", wrpc.ColString)
	msg.AddColumn("filepath", wrpc.ColString)
	msg.AddColumn("filehash", wrpc.ColString)
	msg.StartRow()
	msg.AddRowColumnString(syncpublicid)
	msg.AddRowColumnString(remotefilepath)
	msg.AddRowColumnString(filehash)
	msg.SendDB(wnet)
	//
	// Step 2: Get reply telling us the size of the file we're
	// going to receive
	//
	replmsg, err := wnet.NextMessage()
	if err != nil {
		return err
	}
	if len(replmsg) == 0 {
		// if message is empty, we assume the server closed the connection.
		wnet.Close()
		return errors.New("retrieveFile: Connection closed by same server.")
	}
	reply := wrpc.NewDB()
	reply.ReceiveDB(replmsg)
	if verbose {
		fmt.Println("    Reply received:", reply.GetDBName())
	}
	if reply.GetDBName() == "FileDoesNotExist" {
		if verbose {
			fmt.Println("    File does not exist")
		}
		return errors.New("NoExist")
	}
	if reply.GetDBName() != "ReceiveFile" {
		errmsg, err := reply.GetString(0, 0, 0)
		if err != nil {
			panic(err)
			return errors.New(reply.GetDBName())
		}
		return errors.New("retrieveFile: " + reply.GetDBName() + ": " + errmsg)
	}
	filepath, err := reply.GetString(0, 0, 0)
	if err != nil {
		return err
	}
	filesize, err := reply.GetInt(0, 0, 1)
	if err != nil {
		return err
	}
	modtime, err := reply.GetInt(0, 0, 2)
	if err != nil {
		return err
	}
	receiveFileHash, err := reply.GetString(0, 0, 3)
	if err != nil {
		return err
	}
	modtime -= serverTimeOffset
	if endToEndEncryption {
		filepath, err = decryptDirectoryPath(filepath, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
		if err != nil {
			return err
		}
	}
	if verbose {
		fmt.Println("    File being sent from server:", filepath)
		fmt.Println("    File size:", filesize)
		fmt.Println("    Last modified time:", modtime)
		fmt.Println("    File hash:", receiveFileHash)
	}
	if receiveFileHash != filehash {
		return errors.New("retrieveFile: Received file hash does not match expected file hash.")
	}
	//
	// Step 3: Send ReceiveFileReply with "GoAheadAndSend"
	//
	err = wrpc.SendReplyScalarString("ReceiveFile", version, "GoAheadAndSend", "", wnet)
	if err != nil {
		return err
	}
	//
	// Step 4: Actually receive the bytes of the file
	// while the reply is headed out, we go ahead and start reading
	// the actual file bytes coming in
	//
	var fhOut *os.File
	if verbose {
		fmt.Println("    Attempting to output to file:", localdir, string(os.PathSeparator)+tempFileName)
	}
	fhOut, err = os.Create(samecommon.MakePathSeparatorsForThisOS(localdir + string(os.PathSeparator) + tempFileName))
	if err != nil {
		return errors.New("receiveFile: " + err.Error())
	}
	var bytesread int64
	bytesread = 0
	const bufferSize = 65536
	buffer := make([]byte, bufferSize)
	ciphertext := make([]byte, bufferSize)
	var nIn int
	var nOut int
	var endToEndIvReceived bool
	var endToEndIvIncoming []byte
	var endToEndCipherstreamIn cipher.Stream
	var endToEndBuffer []byte
	var endToEndHasher hash.Hash
	var endToEndActualHmac []byte
	var endToEndFileSizeMinusHMACSignature int64
	thresholdTime := getLocalTime() + 1000000000
	previous := ""
	prec := 0
	for bytesread < filesize {
		currentTime := getLocalTime()
		if currentTime > thresholdTime {
			previous, prec = printPercent(bytesread, filesize, previous, prec)
			thresholdTime = currentTime + 1000000000
		}
		lrest := filesize - bytesread
		if lrest > bufferSize {
			nIn, err = wnet.PullBytes(buffer, ciphertext)
		} else {
			nIn, err = wnet.PullBytes(buffer[:lrest], ciphertext[:lrest])
		}
		if err != nil {
			return errors.New("receiveFile: " + err.Error())
		}
		if endToEndEncryption {
			if !endToEndIvReceived {
				if verbose {
					fmt.Println("End-to-end encryption enabled: decrypting received file.")
				}
				if len(buffer) < aes.BlockSize {
					return errors.New("retrieveFile: Could only read partial AES256 initialization vector.")
				}
				endToEndIvIncoming = make([]byte, aes.BlockSize)
				copy(endToEndIvIncoming, buffer[:aes.BlockSize])
				block, err := aes.NewCipher(endToEndSymmetricKey)
				if err != nil {
					return err
				}
				endToEndBuffer = make([]byte, bufferSize)
				endToEndCipherstreamIn = cipher.NewOFB(block, endToEndIvIncoming)
				endToEndHasher = hmac.New(sha256.New, endToEndHmacKey)
				endToEndActualHmac = make([]byte, 0, 32)
				endToEndCipherstreamIn.XORKeyStream(endToEndBuffer[aes.BlockSize:nIn], buffer[aes.BlockSize:nIn])
				endToEndFileSizeMinusHMACSignature = filesize - 32
				if int64(nIn) > endToEndFileSizeMinusHMACSignature {
					// The whole file is in the buffer
					nOut, err = fhOut.Write(endToEndBuffer[aes.BlockSize:endToEndFileSizeMinusHMACSignature])
					if err != nil {
						return errors.New("receiveFile: " + err.Error())
					}
					if int64(nOut) != (endToEndFileSizeMinusHMACSignature - aes.BlockSize) {
						return errors.New("retrieveFile: Could not write entire buffer out to file for some unknown reason (A).")
					}
					endToEndHasher.Write(buffer[:endToEndFileSizeMinusHMACSignature])
					endToEndActualHmac = append(endToEndActualHmac, buffer[endToEndFileSizeMinusHMACSignature:nIn]...)
				} else {
					// The buffer just has the first portion of the file
					nOut, err = fhOut.Write(endToEndBuffer[aes.BlockSize:nIn])
					if err != nil {
						return errors.New("receiveFile: " + err.Error())
					}
					if nOut != (nIn - aes.BlockSize) {
						return errors.New("retrieveFile: Could not write entire buffer out to file for some unknown reason (B).")
					}
					endToEndHasher.Write(buffer[:nIn])
				}
				endToEndIvReceived = true
			} else {
				if bytesread >= endToEndFileSizeMinusHMACSignature {
					// we are in the HMAC signature
					// capacity should be enough that this append doesn't cause a memory allocation
					endToEndActualHmac = append(endToEndActualHmac, buffer[:nIn]...)
				} else {
					if (bytesread + int64(nIn)) > endToEndFileSizeMinusHMACSignature {
						// The buffer has the end of the file and the beginning or all of the HMAC signature
						stopPoint := endToEndFileSizeMinusHMACSignature - bytesread
						endToEndCipherstreamIn.XORKeyStream(endToEndBuffer[:stopPoint], buffer[:stopPoint])
						nOut, err = fhOut.Write(endToEndBuffer[:stopPoint])
						if err != nil {
							return errors.New("receiveFile: " + err.Error())
						}
						if int64(nOut) != stopPoint {
							return errors.New("retrieveFile: Could not write entire buffer out to file for some unknown reason (D).")
						}
						endToEndHasher.Write(buffer[:stopPoint])
						endToEndActualHmac = append(endToEndActualHmac, buffer[stopPoint:nIn]...)
					} else {
						// The buffer just has a piece of the file, we haven't reached the end.
						endToEndCipherstreamIn.XORKeyStream(endToEndBuffer[:nIn], buffer[:nIn])
						nOut, err = fhOut.Write(endToEndBuffer[:nIn])
						if err != nil {
							return errors.New("receiveFile: " + err.Error())
						}
						if nOut != nIn {
							return errors.New("retrieveFile: Could not write entire buffer out to file for some unknown reason (E).")
						}
						endToEndHasher.Write(buffer[:nIn])
					}
				}
			}
		} else {
			// not using end-to-end encryption
			nOut, err = fhOut.Write(buffer[:nIn])
			if err != nil {
				return errors.New("receiveFile: " + err.Error())
			}
			if nOut != nIn {
				return errors.New("retrieveFile: Could not write entire buffer out to file for some unknown reason (F).")
			}
		}
		bytesread += int64(nIn)
	}
	if endToEndEncryption {
		expectedMAC := endToEndHasher.Sum(nil)
		match := hmac.Equal(endToEndActualHmac, expectedMAC)
		if !match {
			return errors.New("retrieveFile: End-to-end encryption HMAC signature check failed.")
		}
	}
	fhOut.Close()
	if verbose {
		fmt.Println("    File received.")
	}
	//
	// Step 5: Recalculate the local file hash, and make sure it matches the
	// expected file hash. If it does not, we assume we are being hacked and
	// throw it away
	//
	newFileHash := calcHash(localdir + string(os.PathSeparator) + tempFileName)
	if newFileHash != receiveFileHash {
		return errors.New("retrieveFile: Hash verification failed for: " + localdir + string(os.PathSeparator) + tempFileName)
	}
	//
	// Step 6: Now that we have the bytes of the file, rename the
	// file into place, removing the existing file that we have
	// preserved up until this time in case something went wrong
	//
	if verbose {
		fmt.Println("    Renaming", localdir+string(os.PathSeparator)+tempFileName, "to", localdir+samecommon.MakePathSeparatorsForThisOS(filepath))
	}
	finalDestinationPath := samecommon.MakePathSeparatorsForThisOS(localdir + filepath)
	err = os.Rename(localdir+string(os.PathSeparator)+tempFileName, finalDestinationPath)
	if err != nil {
		mkerr := samecommon.MakePathForFile(localdir + samecommon.MakePathSeparatorsForThisOS(filepath))
		if mkerr != nil {
			return errors.New("receiveFile: " + err.Error())
		}
		mverr := os.Rename(localdir+string(os.PathSeparator)+tempFileName, finalDestinationPath)
		if mverr != nil {
			return errors.New("receiveFile: " + err.Error())
		}
	}
	//
	// Step 7: Set the file time. Not doing this will allow our local system
	// to be fooled and think the time we are writing the file right now was
	// the last time the file was edited, possibly giving it a newer time
	// stamp than an actual newer version of the file that exists on some
	// other machine!
	//
	mtime := time.Unix(0, modtime)
	err = os.Chtimes(finalDestinationPath, mtime, mtime) // using same time as both atime and modtime
	if err != nil {
		return err
	}
	//
	// Step 8: Stash all the info about the file in our local database
	//
	if verbose {
		fmt.Println("    Storing updated file time and hash.")
	}
	// We have to get the exact time and size from our disk to keep
	// our local tree scanner from getting confused
	// we take the remote server's word for the file hash, though.
	finalInfo, err := os.Stat(finalDestinationPath)
	if err != nil {
		return err
	}
	finalFileSize := finalInfo.Size()
	finalModTime := finalInfo.ModTime().UnixNano()
	err = stashFileInfo(db, filepath, finalFileSize, finalModTime, filehash)
	if err != nil {
		return errors.New("receiveFile: " + err.Error())
	}
	if verbose {
		fmt.Println("    Sending reception complete message.")
	}
	//
	// Step 9: Tell the server we received the file successfully
	//
	result := "ReceptionComplete"
	errmsg := ""
	wrpc.SendReplyScalarString("ReceiveFile", version, result, errmsg, wnet)
	if verbose {
		fmt.Println("    Reception complete.")
	}
	return nil
}

func rpcMarkFileDeleted(verbose bool, wnet wrpc.IWNetConnection, syncpublicid string, filepath string, filehash string, serverTimeOffset int64, endToEndEncryption bool, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) error {
	modtime := time.Now().UnixNano()
	if verbose {
		fmt.Println("Marking remote file for deletion:", filepath, "with modtime", modtime)
		fmt.Println("    serverTimeOffset", serverTimeOffset)
		fmt.Println("    time sent", modtime+serverTimeOffset)
	}
	var remotePath string
	var err error
	if endToEndEncryption {
		remotePath, err = encryptDirectoryPath(filepath, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
	} else {
		remotePath = filepath
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("MarkFileDeleted", 0, 1)
	rpc.StartTable("", 4, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColString)
	rpc.AddColumn("", wrpc.ColInt)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(syncpublicid)
	rpc.AddRowColumnString(remotePath)
	rpc.AddRowColumnInt(modtime + serverTimeOffset)
	rpc.AddRowColumnString(filehash)
	err = rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "MarkFileDeleted")
	return err
}

func rpcResetUserPassword(wnet wrpc.IWNetConnection, username string) (string, error) {
	if wnet == nil {
		return "", errors.New("Cannot reset user password: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("ResetUserPassword", 0, 1)
	rpc.StartTable("", 1, 1)
	rpc.AddColumn("", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(username)
	err := rpc.SendDB(wnet)
	if err != nil {
		return "", err
	}
	password, err := wrpc.StandardStringReply(wnet, "ResetUserPassword")
	return password, err
}

func rpcUploadAllHashes(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, syncpublicid string, serverTimeOffset int64, endToEndEncryption bool, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) error {
	if wnet == nil {
		return errors.New("Cannot upload hashes: not connected to server.")
	}
	rpc := wrpc.NewDB()
	rpc.StartDB("UploadAllHashes", 0, 2)
	rpc.StartTable("syncpoint", 1, 1)
	rpc.AddColumn("syncpoint", wrpc.ColString)
	rpc.StartRow()
	rpc.AddRowColumnString(syncpublicid)
	rpc.StartTable("hashes", 3, 0)
	rpc.AddColumn("filepath", wrpc.ColString)
	rpc.AddColumn("modtime", wrpc.ColInt)
	rpc.AddColumn("hash", wrpc.ColString)
	cmd := "SELECT filepath, filetime, filehash FROM fileinfo WHERE 1;"
	stmtSel, err := db.Prepare(cmd)
	checkError(err)
	rows, err := stmtSel.Query()
	checkError(err)
	defer rows.Close()
	var filepath string
	var modtime int64
	var filehash string
	for rows.Next() {
		err = rows.Scan(&filepath, &modtime, &filehash)
		checkError(err)
		rpc.StartRow()
		if verbose {
			fmt.Println("    adding file", filepath, "mod time", modtime+serverTimeOffset, "file hash", filehash)
		}
		if endToEndEncryption {
			filepath, err = encryptDirectoryPath(filepath, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
			if err != nil {
				return err
			}
		}
		rpc.AddRowColumnString(filepath)
		rpc.AddRowColumnInt(modtime + serverTimeOffset)
		rpc.AddRowColumnString(filehash)
	}
	err = rpc.SendDB(wnet)
	if err != nil {
		return err
	}
	err = wrpc.StandardVoidReply(wnet, "UploadAllHashes")
	return err
}

// ----------------------------------------------------------------
// End of remote calls
// ----------------------------------------------------------------

func getServerTimeOffset(wnet wrpc.IWNetConnection) (int64, error) {
	localTime1 := getLocalTime()
	var remoteTime int64
	var err error
	remoteTime, err = rpcGetTime(wnet)
	if err != nil {
		return 0, err
	}
	localTime2 := getLocalTime()
	serverTimeOffset := remoteTime - (localTime1 + ((localTime2 - localTime1) >> 1))
	return serverTimeOffset, nil
}

func onOff(bv bool) string {
	if bv {
		return "ON"
	} else {
		return "OFF"
	}
}

func fileExists(filepath string) bool {
	fhFile, err := os.Open(samecommon.MakePathSeparatorsForThisOS(filepath))
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
		return "", nil, errors.New("Looks like we are not in a directory tree that is being synchronized.")
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

func getValue(db *sql.DB, name string, defval string) string {
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
	return value
}

func showConfiguration(db *sql.DB, verbose bool) {
	server := getValue(db, "server", "")
	ptStr := getValue(db, "port", "0")
	port := strToInt(ptStr)
	username := getValue(db, "username", "")
	password := getValue(db, "password", "")
	syncPointID := getValue(db, "syncpointid", "")
	fmt.Println("Server:", server)
	fmt.Println("Port:", port)
	fmt.Println("Username (email):", username)
	fmt.Println("Password:", password)
	fmt.Println("Sync point ID:", syncPointID)
	serverSymKeyStr := getValue(db, "serversymkey", "")
	if serverSymKeyStr != "" {
		fmt.Print("Server key: ")
		fmt.Print(serverSymKeyStr)
		serverHmacKeyStr := getValue(db, "serverhmackey", "")
		fmt.Println(serverHmacKeyStr)
	}
	endToEndSymKeyStr := getValue(db, "endtoendsymkey", "")
	if endToEndSymKeyStr != "" {
		fmt.Print("End-to-end encryption key: ")
		fmt.Print(endToEndSymKeyStr)
		endToEndHmacKeyStr := getValue(db, "endtoendhmackey", "")
		fmt.Print(endToEndHmacKeyStr)
		endToEndIvStr := getValue(db, "endtoendinitializationvector", "")
		fmt.Println(endToEndIvStr)
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
func getDirectoryTree(verbose bool, path string, result []samecommon.SameFileInfo, skipIfPermissionDenied bool) ([]samecommon.SameFileInfo, error) {
	if verbose {
		fmt.Println("Scanning: " + path)
	}
	dir, err := os.Open(samecommon.MakePathSeparatorsForThisOS(path))
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
					fmt.Println(completePath, "size", filestuff.Size(), "bytes, last modified", calcTimeFromNow(filestuff.ModTime().UnixNano()), "seconds ago")
				}
				result = append(result, samecommon.SameFileInfo{completePath, filestuff.Size(), filestuff.ModTime().UnixNano(), "", false})
			}
		}
	}
	return result, nil
}

func (ptr *fileSortSlice) Len() int {
	return len(ptr.theSlice)
}

func (ptr *fileSortSlice) Less(i, j int) bool {
	return ptr.theSlice[i].FilePath < ptr.theSlice[j].FilePath
}

func (ptr *fileSortSlice) Swap(i, j int) {
	filePath := ptr.theSlice[i].FilePath
	ptr.theSlice[i].FilePath = ptr.theSlice[j].FilePath
	ptr.theSlice[j].FilePath = filePath
	fileSize := ptr.theSlice[i].FileSize
	ptr.theSlice[i].FileSize = ptr.theSlice[j].FileSize
	ptr.theSlice[j].FileSize = fileSize
	fileTime := ptr.theSlice[i].FileTime
	ptr.theSlice[i].FileTime = ptr.theSlice[j].FileTime
	ptr.theSlice[j].FileTime = fileTime
	fileHash := ptr.theSlice[i].FileHash
	ptr.theSlice[i].FileHash = ptr.theSlice[j].FileHash
	ptr.theSlice[j].FileHash = fileHash
	reUpNeeded := ptr.theSlice[i].ReUpNeeded
	ptr.theSlice[i].ReUpNeeded = ptr.theSlice[j].ReUpNeeded
	ptr.theSlice[j].ReUpNeeded = reUpNeeded
}

func calcHash(filePath string) string {
	fileHandle, err := os.Open(samecommon.MakePathSeparatorsForThisOS(filePath))
	checkError(err)
	defer fileHandle.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, fileHandle)
	checkError(err)
	encoded := hex.EncodeToString(hash.Sum(nil))
	return encoded
}

func putTreeInTableAndFillInHashesThatNeedToBeUpdated(verbose bool, db *sql.DB, tree []samecommon.SameFileInfo, basePath string) {
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
		filterOutCheck := tree[ii].FilePath[chopOff+1:]
		if (filterOutCheck != databaseFileName) && (filterOutCheck != tempFileName) {
			if verbose {
				fmt.Print(tree[ii].FilePath[chopOff:])
			}
			rowsCheck, err := stmtSelCheck.Query(tree[ii].FilePath[chopOff:])
			checkError(err)
			defer rowsCheck.Close()
			var fileid int64
			fileid = 0
			for rowsCheck.Next() {
				rowsCheck.Scan(&fileid, &filesize, &filetime, &oldFileHash)
			}
			if fileid == 0 {
				fileHash := calcHash(tree[ii].FilePath)
				if verbose {
					fmt.Println(" - NEW, original hash is:", fileHash)
				}
				tree[ii].FileHash = fileHash
				_, err := stmtIns.Exec(samecommon.MakePathSeparatorsStandard(tree[ii].FilePath[chopOff:]), tree[ii].FileSize, tree[ii].FileTime, fileHash)
				checkError(err)
			} else {
				if (filesize == tree[ii].FileSize) && (filetime == tree[ii].FileTime) && (oldFileHash != "deleted") && (oldFileHash != "") {
					// assume hasn't changed -- leave alone!
					if verbose {
						fmt.Println(" - Has not changed")
					}
					tree[ii].FileHash = oldFileHash
				} else {
					fileHash := calcHash(tree[ii].FilePath)
					if verbose {
						fmt.Println(" - CHANGED, new hash:", fileHash)
					}
					tree[ii].FileHash = fileHash
					_, err := stmtUpd.Exec(tree[ii].FileSize, tree[ii].FileTime, fileHash, fileid)
					checkError(err)
				}
				delete(deleteMap, fileid)
			}
		}
	}
	for fileid, _ = range deleteMap {
		currentTime := time.Now().UnixNano()
		if verbose {
			fmt.Println("marking file ID", fileid, "as deleted with current time", currentTime)
		}
		_, err := stmtUpMarkDel.Exec(currentTime, fileid)
		checkError(err)
	}
	err = tx.Commit()
	checkError(err)
}

func retrieveTreeFromDB(verbose bool, db *sql.DB) []samecommon.SameFileInfo {
	tx, err := db.Begin()
	checkError(err)

	result := make([]samecommon.SameFileInfo, 0)

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
		result = append(result, samecommon.SameFileInfo{filepath, filesize, filetime, filehash, false})
	}
	err = tx.Commit()
	checkError(err)

	return result
}

func removeExtraneousFileFromLocalDB(verbose bool, db *sql.DB, filepath string) error {
	if verbose {
		fmt.Println("Removing extranneous file from local DB:", filepath)
	}
	cmd := "SELECT fileid FROM fileinfo WHERE filepath = ?;"
	stmtSel, err := db.Prepare(cmd)
	checkError(err)
	rows, err := stmtSel.Query(filepath)
	var fileid int64
	fileid = 0
	for rows.Next() {
		rows.Scan(&fileid)
	}
	if fileid == 0 {
		panic("filepath not found in local DB when attempting to remove extraneous file from local DB")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	cmd = "DELETE FROM fileinfo WHERE fileid = ?;"
	stmtDel, err := tx.Prepare(cmd)
	if err != nil {
		tx.Rollback()
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	_, err = stmtDel.Exec(fileid)
	if err != nil {
		tx.Rollback()
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	err = tx.Commit()
	checkError(err)
	return nil
}

func synchronizeTrees(verbose bool, db *sql.DB, wnet wrpc.IWNetConnection, syncpublicid string, localPath string, localTree []samecommon.SameFileInfo, remotePath string, remoteTree []samecommon.SameFileInfo, serverTimeOffset int64, runForever bool, endToEndEncryption bool, endToEndIV []byte, endToEndSymmetricKey []byte, endToEndHmacKey []byte) {
	filterDatabaseFile := "/" + databaseFileName
	filterTempFile := "/" + tempFileName
	localIdx := 0
	remoteIdx := 0
	anythingChanged := false
	for (localIdx < len(localTree)) || (remoteIdx < len(remoteTree)) {
		toUploadLocal := -1    // -1 is used as a magic value to indicate not to copy
		toDownloadRemote := -1 // -1 is used as a magic value to indicate not to copy
		toDeleteRemote := -1   // -1 is used as a magic value to indicate not to delete
		toDeleteLocal := -1    // -1 is used as a magic value to indicate not to delete
		if localIdx == len(localTree) {
			if verbose {
				fmt.Println("Off end of local tree")
				fmt.Println("Remote file is", remoteTree[remoteIdx].FilePath)
			}
			if remoteTree[remoteIdx].FileHash == "deleted" {
				if verbose {
					fmt.Println("Remote file is marked as deleted, so we won't attempt to download it")
				}
			} else {
				toDownloadRemote = remoteIdx
			}
			remoteIdx++
		} else {
			localCompare := localTree[localIdx].FilePath
			if remoteIdx == len(remoteTree) {
				if verbose {
					fmt.Println("Off end of remote tree")
				}
				if localTree[localIdx].FileHash == "deleted" {
					if verbose {
						fmt.Println("Local file is deleted, no remote file to delete so we do nothing.")
					}
				} else {
					toUploadLocal = localIdx
					if verbose {
						fmt.Println("Local file is marked to upload")
					}
				}
				localIdx++
			} else {
				remoteCompare := remoteTree[remoteIdx].FilePath
				if verbose {
					fmt.Println("Comparing", localCompare, "with", remoteCompare)
				}
				if localCompare == remoteCompare {
					if verbose {
						fmt.Println("File names are the same -- comparing file hashes.")
					}
					if localTree[localIdx].FileHash != remoteTree[remoteIdx].FileHash {
						if verbose {
							fmt.Println("File hashes are different -- determining which is newer.")
							fmt.Println(" Local file time is:", localTree[localIdx].FileTime)
							fmt.Println("Remote file time is:", remoteTree[remoteIdx].FileTime)
						}
						if localTree[localIdx].FileTime > remoteTree[remoteIdx].FileTime {
							if localTree[localIdx].FileHash == "deleted" {
								if remoteTree[remoteIdx].FileHash == "deleted" {
									if verbose {
										fmt.Println("Local file is newer but local file is deleted but remote file is also deleted, so doing nothing.")
									}
								} else {
									toDeleteRemote = remoteIdx
									if verbose {
										fmt.Println("Local file is newer but local file is deleted -- marked remote file to be deleted")
									}
								}
							} else {
								toUploadLocal = localIdx
								if verbose {
									fmt.Println("Local file is newer -- marked to upload")
								}
							}
						} else {
							if remoteTree[remoteIdx].FileHash == "deleted" {
								if localTree[localIdx].FileHash == "deleted" {
									if verbose {
										fmt.Println("Local file is newer but local file is deleted but remote file is also deleted, so doing nothing.")
										fmt.Println("Remote file is newer and deleted but local file is also deleted, so doing nothing.")
									}
								} else {
									toDeleteLocal = localIdx
									if verbose {
										fmt.Println("Remote file is newer and deleted -- marked local file to be deleted")
									}
								}
							} else {
								toDownloadRemote = remoteIdx
								if verbose {
									fmt.Println("Remote file is newer -- marked to download")
								}
							}
						}
					} else {
						if verbose {
							fmt.Println("Hashes match.")
						}
						if remoteTree[remoteIdx].ReUpNeeded {
							toUploadLocal = localIdx
							if verbose {
								fmt.Println("Reupload needed -- marked to upload")
							}
						}
					}
					localIdx++
					remoteIdx++
				} else {
					if verbose {
						fmt.Println("File names are different -- figure out which is first in alphabetical order.")
					}
					if localCompare < remoteCompare {
						if verbose {
							fmt.Println("File names are different, local is first")
						}
						if localTree[localIdx].FileHash == "deleted" {
							if verbose {
								fmt.Println("Local file is newer and deleted -- no remote file to delete, so doing nothing.")
							}
						} else {
							toUploadLocal = localIdx
							if verbose {
								fmt.Println("Local file is not deleted -- marked to upload")
							}
						}
						localIdx++
					} else {
						if verbose {
							fmt.Println("File names are different, remote is first")
						}
						if remoteTree[remoteIdx].FileHash == "deleted" {
							if verbose {
								fmt.Println("Remote file is newer and deleted -- no corresponding local file, so doing nothing.")
							}
						} else {
							if verbose {
								fmt.Println("Remote file is not deleted -- marked to download")
							}
							toDownloadRemote = remoteIdx
						}
						remoteIdx++
					}
				}
			}
		}
		if toUploadLocal >= 0 {
			if (localTree[toUploadLocal].FilePath != filterDatabaseFile) && (localTree[toUploadLocal].FilePath != filterTempFile) { // filter out ourselves
				if !anythingChanged {
					if runForever {
						fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
					}
					anythingChanged = true
				}
				fmt.Println("Pushing -->", localTree[toUploadLocal].FilePath[1:])
				localfilepath := localPath + localTree[toUploadLocal].FilePath
				filehash := localTree[toUploadLocal].FileHash
				err := sendFile(verbose, wnet, syncpublicid, localPath, localfilepath, filehash, serverTimeOffset, endToEndEncryption, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
				if err != nil {
					if err.Error() != "CANNOT_STAT" {
						fmt.Fprintln(os.Stderr, err)
						return
					}
					err = removeExtraneousFileFromLocalDB(verbose, db, localTree[toUploadLocal].FilePath)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return
					}
				}
			}
		}
		if toDownloadRemote >= 0 {
			if (remoteTree[toDownloadRemote].FilePath != filterDatabaseFile) && (remoteTree[toDownloadRemote].FilePath != filterTempFile) { // filter out ourselves
				if !anythingChanged {
					if runForever {
						fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
					}
					anythingChanged = true
				}
				fmt.Println("Pulling <--", remoteTree[toDownloadRemote].FilePath[1:])
				localfilepath := localPath + remoteTree[toDownloadRemote].FilePath
				filehash := remoteTree[toDownloadRemote].FileHash
				err := retrieveFile(verbose, db, wnet, syncpublicid, localPath, localfilepath, filehash, serverTimeOffset, endToEndEncryption, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
				if err != nil {
					errmsg := err.Error()
					if errmsg == "NoExist" {
						fmt.Println("    File no longer exists on the server. File is flagged for re-upload. Run same on the machine with the last uploaded version to re-upload it.")
					} else {
						fmt.Fprintln(os.Stderr, errmsg)
						panic(errmsg)
					}
				}
			}
		}
		if toDeleteRemote >= 0 {
			if (remoteTree[toDeleteRemote].FilePath != filterDatabaseFile) && (remoteTree[toDeleteRemote].FilePath != filterTempFile) { // filter out ourselves
				if !anythingChanged {
					if runForever {
						fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
					}
					anythingChanged = true
				}
				fmt.Println("Pushing delete notification:", remoteTree[toDeleteRemote].FilePath[1:])
				remotefilepath := remoteTree[toDeleteRemote].FilePath
				filehash := remoteTree[toDeleteRemote].FileHash
				err := rpcMarkFileDeleted(verbose, wnet, syncpublicid, remotefilepath, filehash, serverTimeOffset, endToEndEncryption, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
				if err != nil {
					fmt.Fprintln(os.Stderr, err.Error())
					panic(err)
				}
			}
		}
		if toDeleteLocal >= 0 {
			if (localTree[toDeleteLocal].FilePath != filterDatabaseFile) && (localTree[toDeleteLocal].FilePath != filterTempFile) { // filter out ourselves
				if !anythingChanged {
					if runForever {
						fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
					}
					anythingChanged = true
				}
				fmt.Println("Deleting:", localTree[toDeleteLocal].FilePath[1:])
				localfilepath := localPath + samecommon.MakePathSeparatorsForThisOS(localTree[toDeleteLocal].FilePath)
				if verbose {
					fmt.Println("Deleting local file path:", localfilepath)
				}
				os.Remove(localfilepath)
			}
		}
	}
}

func dumpTree(tree []samecommon.SameFileInfo) {
	for _, fileinfo := range tree {
		fmt.Println(fileinfo.FilePath)
	}
}

// Functions for Admin Mode

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

func recalculateAllFileHashes(verbose bool, db *sql.DB, rootPath string) {
	var sortSlice fileSortSlice
	localTree := make([]samecommon.SameFileInfo, 0)
	localTree, err := getDirectoryTree(verbose, rootPath, localTree, false)
	checkError(err)
	sortSlice.theSlice = localTree
	sort.Sort(&sortSlice)
	basePath := rootPath // redundant copy
	if verbose {
		fmt.Println("base path:", basePath)
	}
	if verbose {
		fmt.Println("Clearing out previous file hashes")
	}
	// Here we TRUNCATE our hash table and start over!
	tx, err := db.Begin()
	if err != nil {
		tx.Rollback()
		fmt.Fprintln(os.Stderr, err)
		return
	}
	cmd := "DELETE FROM fileinfo;"
	stmtTruncate, err := tx.Prepare(cmd)
	if err != nil {
		tx.Rollback()
		fmt.Fprintln(os.Stderr, err)
		return
	}
	_, err = stmtTruncate.Exec()
	if err != nil {
		tx.Rollback()
		fmt.Fprintln(os.Stderr, err)
		return
	}
	err = tx.Commit()
	checkError(err)
	// And now proceed as normal!
	if verbose {
		fmt.Println("Recalculating all file hashes")
	}
	putTreeInTableAndFillInHashesThatNeedToBeUpdated(verbose, db, localTree, basePath)
}

func doAdminMode(wnet wrpc.IWNetConnection, db *sql.DB, rootPath string, verbose bool) {
	keyboard := bufio.NewReader(os.Stdin)
	fmt.Print("Admin password: ")
	password := getLine(keyboard)
	err := rpcLogin(wnet, "admin", password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	for {
		fmt.Print("> ")
		command, err := keyboard.ReadString('\n')
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
			case "show":
				if len(params) == 1 {
					fmt.Println("Show what?")
					fmt.Println("    users -- show users")
					fmt.Println("    syncpoints -- show sync points")
					fmt.Println("    grants -- show access grants of users to sync points")
				} else {
					switch params[1] {
					case "users":
						err = rpcListUsers(wnet)
						if err != nil {
							fmt.Fprintln(os.Stderr, err)
						}
					case "syncpoints":
						server := getValue(db, "server", "")
						if verbose {
							fmt.Println("server =", server)
						}
						err = rpcListSyncPoints(wnet, server)
						if err != nil {
							fmt.Fprintln(os.Stderr, err)
						}
					case "grants":
						err = rpcListGrants(wnet)
						if err != nil {
							fmt.Fprintln(os.Stderr, err)
						}
					default:
						fmt.Println("List: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "add":
				if len(params) == 1 {
					fmt.Println("Add what?")
					fmt.Println("    user -- add user")
					fmt.Println("    syncpoint -- add sync point on server")
					fmt.Println("    grant -- grant a user access to a sync point")
				} else {
					switch params[1] {
					case "user":
						fmt.Print("Username (email): ")
						username := getLine(keyboard)
						if verbose {
							fmt.Println("The username you entered is:", username)
						}
						password, err := rpcAddUser(wnet, username, samecommon.RoleSyncPointUser)
						if err != nil {
							if verbose {
								fmt.Println("adduser failed.")
							}
							fmt.Fprintln(os.Stderr, err)
						} else {
							fmt.Println("User created. Password is:")
							fmt.Println(password)
							yes := getYesNo(keyboard, "Set as username and password for this client? (y/n) ")
							if yes {
								err = samecommon.SetNameValuePair(db, "username", username)
								if err != nil {
									fmt.Fprintln(os.Stderr, err)
								}
								if verbose {
									fmt.Println("username set to", username)
								}
								samecommon.SetNameValuePair(db, "password", password)
								if err != nil {
									fmt.Fprintln(os.Stderr, err)
								}
								if verbose {
									fmt.Println("password set to", password)
								}
							}
						}
					case "syncpoint":
						path := ""
						for path == "" {
							fmt.Print("Path on server: ")
							path = getLine(keyboard)
						}
						publicid, err := rpcAddSyncPoint(wnet, path)
						if err != nil {
							if verbose {
								fmt.Println("Could not add sync point.")
							}
							fmt.Fprintln(os.Stderr, err)
						} else {
							fmt.Println("The sync point ID is:")
							fmt.Println(publicid)
							yes := getYesNo(keyboard, "Set key as sync point for this client? (y/n) ")
							if yes {
								samecommon.SetNameValuePair(db, "syncpointid", publicid)
								if err != nil {
									fmt.Println(os.Stderr, err)
								}
								if verbose {
									fmt.Println("syncpointid set to", publicid)
								}
							}
						}
					case "grant":
						username := ""
						for username == "" {
							fmt.Print("Username (email): ")
							username = getLine(keyboard)
						}
						syncpublicid := ""
						for syncpublicid == "" {
							fmt.Print("Sync point ID: ")
							syncpublicid = getLine(keyboard)
						}
						access := 0
						yes := getYesNo(keyboard, "Grant read access? (y/n) ")
						if yes {
							access |= samecommon.AccessRead
						}
						yes = getYesNo(keyboard, "Grant write access? (y/n) ")
						if yes {
							access |= samecommon.AccessWrite
						}
						err = rpcAddGrant(wnet, username, syncpublicid, access)
						if err != nil {
							fmt.Fprintln(os.Stderr, err)
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
						fmt.Print("Username (email): ")
						username := getLine(keyboard)
						if verbose {
							fmt.Println("The username you entered is:", username)
						}
						err = rpcDeleteUser(wnet, username)
						if err != nil {
							if verbose {
								fmt.Println("del user failed.")
							}
							fmt.Fprintln(os.Stderr, err)
						}
					case "syncpoint":
						syncpublicid := ""
						for syncpublicid == "" {
							fmt.Print("Sync point ID: ")
							syncpublicid = getLine(keyboard)
						}
						fmt.Println("Are you sure? Doing this will permanently prevent this server directory from")
						fmt.Println("ever being used as a syncpoint in the future. You will need to start with a new")
						fmt.Println("blank directory on the server if you want these files synced again. All access")
						fmt.Println("grants will be deleted and will need to be set up again if you ever want this")
						yes := getYesNo(keyboard, "sync point back. Are you really sure you want to do this? (y/n) ")
						if yes {
							err = rpcDeleteSyncPoint(wnet, syncpublicid)
							if err != nil {
								if verbose {
									fmt.Println("Could not add sync point.")
								}
								fmt.Fprintln(os.Stderr, err)
							}
						}
					case "grant":
						username := ""
						for username == "" {
							fmt.Print("Username (email): ")
							username = getLine(keyboard)
						}
						syncpublicid := ""
						for syncpublicid == "" {
							fmt.Print("Sync point ID: ")
							syncpublicid = getLine(keyboard)
						}
						err = rpcDeleteGrant(wnet, username, syncpublicid)
						if err != nil {
							if verbose {
								fmt.Println("Could not add grant")
							}
							fmt.Fprintln(os.Stderr, err)
						}
					default:
						fmt.Println("Delete: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "reset":
				if len(params) == 1 {
					fmt.Println("Reset what?")
					fmt.Println("    user password -- reset user password")
				} else {
					switch params[1] {
					case "user":
						if len(params) == 2 {
							fmt.Println("Reset user what?")
							fmt.Println("    password -- reset user password")
						} else {
							switch params[2] {
							case "password":
								fmt.Print("Username (email): ")
								username := getLine(keyboard)
								if verbose {
									fmt.Println("The username you entered is:", username)
								}
								password, err := rpcResetUserPassword(wnet, username)
								if err != nil {
									fmt.Fprintln(os.Stderr, err)
								} else {
									fmt.Println("New password:")
									fmt.Println(password)
									localUsername := getValue(db, "username", "")
									if verbose {
										fmt.Println("username =", localUsername)
									}
									if username == localUsername {
										yes := getYesNo(keyboard, "Set as password for this client? (y/n) ")
										if yes {
											samecommon.SetNameValuePair(db, "password", password)
											if err != nil {
												fmt.Fprintln(os.Stderr, err)
											} else {
												if verbose {
													fmt.Println("password set to", password)
												}
											}
										}
									}
								}
							default:
								fmt.Println("Reset user: " + `"` + params[2] + `"` + " not found.")
							}
						}
					default:
						fmt.Println("Reset : " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "repair":
				if len(params) == 1 {
					fmt.Println("repair what?")
					fmt.Println("    upload hashes -- set the file hashes on the server to an upload from the local system")
				} else {
					switch params[1] {
					case "upload":
						if len(params) == 2 {
							fmt.Println("repair upload what?")
							fmt.Println("    hashes -- set the file hashes on the server to an upload from the local system")
						} else {
							switch params[2] {
							case "hashes":
								fmt.Println("This operation will overwrite all the hashes on the server to a copy of the")
								fmt.Println("local file hashes. This should only be done to repair a damaged installation or")
								fmt.Println("during an upgrade operation. If doing an upgrade, you must make sure all clients")
								fmt.Println("are fully synchronized before upgrading the software of either clients or")
								fmt.Println("servers and before performing this operation. This operation should never be")
								yes := getYesNo(keyboard, "used as part of day-to-day operation. Are you sure you wish to continue? (y/n) ")
								if yes {
									if verbose {
										fmt.Println("Recalculating all file hashes.")
									}
									recalculateAllFileHashes(verbose, db, rootPath)
									if verbose {
										fmt.Println("All file hashes recalculated.")
									}
									if verbose {
										fmt.Println("Obtaining server time offset.")
									}
									serverTimeOffset, err := getServerTimeOffset(wnet)
									if err != nil {
										fmt.Fprintln(os.Stderr, err)
									} else {
										if verbose {
											fmt.Println("Uploading all file hashes to the server.")
										}
										syncPointID := getValue(db, "syncpointid", "")
										if verbose {
											fmt.Println("Sync point ID:", syncPointID)
										}
										endToEndEncryption := false
										var endToEndIV []byte
										var endToEndSymmetricKey []byte
										var endToEndHmacKey []byte
										endToEndSymKeyStr := getValue(db, "endtoendsymkey", "")
										if endToEndSymKeyStr != "" {
											endToEndSymmetricKey, err = hex.DecodeString(endToEndSymKeyStr)
											if err != nil {
												fmt.Fprintln(os.Stderr, err)
												return
											}
											endToEndHmacKeyStr := getValue(db, "endtoendhmackey", "")
											endToEndHmacKey, err = hex.DecodeString(endToEndHmacKeyStr)
											if err != nil {
												fmt.Fprintln(os.Stderr, err)
												return
											}
											endToEndIvStr := getValue(db, "endtoendinitializationvector", "")
											endToEndIV, err = hex.DecodeString(endToEndIvStr)
											if err != nil {
												fmt.Fprintln(os.Stderr, err)
												return
											}
											endToEndEncryption = true
										}
										if verbose {
											if endToEndEncryption {
												fmt.Println("End-to-end encryption is enabled.")
											}
										}
										err = rpcUploadAllHashes(verbose, db, wnet, syncPointID, serverTimeOffset, endToEndEncryption, endToEndIV, endToEndSymmetricKey, endToEndHmacKey)
										if err != nil {
											fmt.Fprintln(os.Stderr, err)
										} else {
											if verbose {
												fmt.Println("All file hashes uploaded.")
											}
										}
									}
								}
							default:
								fmt.Println("repair upload: " + `"` + params[2] + `"` + " not found.")
							}
						}
					default:
						fmt.Println("repair: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "local":
				if len(params) == 1 {
					fmt.Println("local what?")
					fmt.Println("    show config -- show configuration on local machine")
					fmt.Println("    repair hashes -- rescan local system and recalculate all hashes")
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
					case "repair":
						if len(params) == 2 {
							fmt.Println("local repair what?")
							fmt.Println("    hashes -- rescan local system and recalculate all hashes")
						} else {
							switch params[2] {
							case "hashes":
								fmt.Println("This function to rescan all hashes is a repair function and should only be used")
								fmt.Println("as part of repairing or upgrading a samesync installation. It should not be")
								yes := getYesNo(keyboard, "used as part of day-to-day operation. Are you sure you wish to continue? (y/n) ")
								if yes {
									if verbose {
										fmt.Println("Recalculating all file hashes.")
									}
									recalculateAllFileHashes(verbose, db, rootPath)
									if verbose {
										fmt.Println("All file hashes recalculated.")
									}
								}
							default:
								fmt.Println("local recalc: " + `"` + params[2] + `"` + " not found.")
							}
						}
					default:
						fmt.Println("local: " + `"` + params[1] + `"` + " not found.")
					}
				}
			case "help":
				fmt.Println("show")
				fmt.Println("    users -- show users")
				fmt.Println("    syncpoints -- show sync points")
				fmt.Println("    grants -- show access grants of users to sync points")
				fmt.Println("add")
				fmt.Println("    user -- add user")
				fmt.Println("    syncpoint -- add sync point on server")
				fmt.Println("    grant -- grant a user access to a sync point")
				fmt.Println("del")
				fmt.Println("    user -- delete user")
				fmt.Println("    syncpoint -- delete sync point from server")
				fmt.Println("    grant -- revoke a user's access to a sync point")
				fmt.Println("reset")
				fmt.Println("    user")
				fmt.Println("        password -- reset user password")
				fmt.Println("repair")
				fmt.Println("    upload")
				fmt.Println("        hashes -- set the file hashes on the server to an upload from the local system")
				fmt.Println("local")
				fmt.Println("    show")
				fmt.Println("        config -- show local machine current configuration")
				fmt.Println("    repair")
				fmt.Println("        hashes -- rescan local system and recalculate all hashes")
				fmt.Println("help -- this message")
				fmt.Println("quit -- exit program")
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

func quickSetupReadConfigFile(configFile string) (map[string]string, error) {
	nameValuePairs := make(map[string]string)
	fhConfig, err := os.Open(configFile)
	if err != nil {
		return nameValuePairs, err
	}
	defer fhConfig.Close()
	fhIn := bufio.NewReader(fhConfig)
	keepGoing := true
	for keepGoing {
		inLine, err := fhIn.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				keepGoing = false
			} else {
				checkError(err)
			}
		} else {
			inLine = trim(inLine)
			ii := strings.Index(inLine, ": ")
			if ii >= 0 {
				keyname := inLine[:ii]
				value := inLine[ii+2:]
				// we filter the list to only our allowed values in case someone tries to hack the config file
				if (keyname == "username") || (keyname == "password") || (keyname == "syncpointid") || (keyname == "serversymkey") || (keyname == "serverhmackey") || (keyname == "endtoendsymkey") || (keyname == "endtoendhmackey") || (keyname == "endtoendinitializationvector") {
					// We verify binary fields are encoded as binary fields
					if keyname == "password" {
						passwordBin := make([]byte, 64)
						ndst, _, err := ascii85.Decode(passwordBin, []byte(value), true)
						if err != nil {
							return nameValuePairs, err
						}
						if ndst != 64 {
							fmt.Fprintln(os.Stderr, "Password is invalid")
							return nameValuePairs, errors.New("Password is invalid")
						}
						if len(passwordBin) != 64 {
							fmt.Fprintln(os.Stderr, "Password is invalid")
							return nameValuePairs, errors.New("Password is invalid")
						}
					}
					if (keyname == "syncpointid") || (keyname == "serversymkey") || (keyname == "serverhmackey") || (keyname == "endtoendsymkey") || (keyname == "endtoendhmackey") || (keyname == "endtoendinitializationvector") {
						_, err := hex.DecodeString(value)
						if err != nil {
							fmt.Fprintln(os.Stderr, "An encryption key is improperly encoded.")
							return nameValuePairs, err
						}
					}
				}
				nameValuePairs[keyname] = value
			}
		}
	}
	return nameValuePairs, nil
}

func checkForNestingAndInitializeDB(verbose bool, rootPath string, currentPath string, useFile string) (*sql.DB, error) {
	var err error
	var db *sql.DB
	if verbose {
		fmt.Println("Creating state file in current directory.")
	}
	rootPath, db, err = getStateDB(currentPath, useFile, databaseFileName, verbose)
	if rootPath != "" {
		return db, errors.New("You cannot create a syncronized directory inside another synchronized directory.")
	}
	localTree := make([]samecommon.SameFileInfo, 0)
	localTree, err = getDirectoryTree(verbose, currentPath, localTree, false)
	for ii := 0; ii < len(localTree); ii++ {
		if localTree[ii].FilePath[len(localTree[ii].FilePath)-len(databaseFileName):] == databaseFileName {
			return db, errors.New("You cannot create a syncronized directory inside another synchronized directory.")
		}
	}
	db, err = sql.Open("sqlite3", currentPath+string(os.PathSeparator)+databaseFileName)
	checkError(err)
	initializeDatabase(db)
	return db, nil
}

func doQuickSetup(verbose bool, currentPath string, defaultStateFileName string, useFile string) {
	rootPath := findRootPath(currentPath, defaultStateFileName)
	if rootPath != "" {
		fmt.Println("Looks like we are already set up to sync this directory.")
		fmt.Println("No need to do setup twice.")
		return
	}
	var configFile string
	if useFile == "" {
		configFile = "../samesetup.txt"
	} else {
		configFile = useFile
	}
	configInfo, err := quickSetupReadConfigFile(configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	_, ok := configInfo["endtoendsymkey"]
	if !ok {
		fmt.Println("Config file is missing end-to-end encryption key.")
		fhConfigOut, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		endToEndSymBin, err := samecommon.GenerateAESKey()
		checkError(err)
		endToEndSymKeyStr := hex.EncodeToString(endToEndSymBin)
		endToEndHmacBin, err := samecommon.GenerateAESKey()
		checkError(err)
		endToEndHmacKeyStr := hex.EncodeToString(endToEndHmacBin)
		endToEndIvBin, err := samecommon.GenerateAESInitializationVector()
		checkError(err)
		endToEndIvStr := hex.EncodeToString(endToEndIvBin)
		err = samecommon.SetupWriteSettingToConfigFile(fhConfigOut, "endtoendsymkey", endToEndSymKeyStr)
		checkError(err)
		err = samecommon.SetupWriteSettingToConfigFile(fhConfigOut, "endtoendhmackey", endToEndHmacKeyStr)
		checkError(err)
		err = samecommon.SetupWriteSettingToConfigFile(fhConfigOut, "endtoendinitializationvector", endToEndIvStr)
		checkError(err)
		fmt.Println("Since the end-to-end encryption key was missing from the samesetup.txt")
		fmt.Println("configuration file, an end-to-end key was generated and added to the file. Use")
		fmt.Println("the samesetup.txt file from this machine to set up all other clients, so the")
		fmt.Println("end-to-end encryption key is the same on all the clients.")
		fhConfigOut.Close()
	}
	configInfo, err = quickSetupReadConfigFile(configFile)
	fmt.Println("Configuration file", configFile, "read.")
	fmt.Println("The server and port number are not in the configuration file so if an attacker")
	fmt.Println("should accidently get hold of the file, they won't know what it accesses. You")
	fmt.Println("will need to enter these manually on every client.")
	keyboard := bufio.NewReader(os.Stdin)
	var server string
	for server == "" {
		fmt.Print("Server: ")
		server = getLine(keyboard)
	}
	port := 0
	for port == 0 {
		fmt.Print("Port: ")
		ptStr := getLine(keyboard)
		if ptStr != "" {
			port = strToInt(ptStr)
		}
	}
	var db *sql.DB
	db, err = checkForNestingAndInitializeDB(verbose, rootPath, currentPath, useFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	samecommon.SetNameValuePair(db, "server", server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("server set to", server)
	}
	samecommon.SetNameValuePair(db, "port", intToStr(port))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("port set to", intToStr(port))
	}
	samecommon.SetNameValuePair(db, "username", configInfo["username"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("username set to", configInfo["username"])
	}
	samecommon.SetNameValuePair(db, "password", configInfo["password"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("password set to", configInfo["password"])
	}
	samecommon.SetNameValuePair(db, "syncpointid", configInfo["syncpointid"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("syncpointid", configInfo["syncpointid"])
	}
	samecommon.SetNameValuePair(db, "serversymkey", configInfo["serversymkey"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("serversymkey set to", configInfo["serversymkey"])
	}
	samecommon.SetNameValuePair(db, "serverhmackey", configInfo["serverhmackey"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("serverhmackey set to", configInfo["serverhmackey"])
	}
	samecommon.SetNameValuePair(db, "endtoendsymkey", configInfo["endtoendsymkey"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("endtoendsymkey set to", configInfo["endtoendsymkey"])
	}
	samecommon.SetNameValuePair(db, "endtoendhmackey", configInfo["endtoendhmackey"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("endtoendhmackey set to", configInfo["endtoendhmackey"])
	}
	samecommon.SetNameValuePair(db, "endtoendinitializationvector", configInfo["endtoendinitializationvector"])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if verbose {
		fmt.Println("endtoendinitializationvector set to", configInfo["endtoendinitializationvector"])
	}
	fmt.Println("Configuration is complete!")
}

func main() {
	currentPath, err := os.Getwd()
	checkError(err)
	vflag := flag.Bool("v", false, "verbose")
	cflag := flag.Bool("c", false, "configure")
	iflag := flag.Bool("i", false, "initialize")
	fflag := flag.String("f", "", "use specified file")
	jflag := flag.Bool("j", false, "show server key")
	kflag := flag.Bool("k", false, "import server key")
	sflag := flag.Bool("s", false, "show configuration")
	aflag := flag.Bool("a", false, "admin mode")
	gflag := flag.Bool("g", false, "generate end-to-end encryption key")
	eflag := flag.Bool("e", false, "import end-to-end encryption key")
	xflag := flag.Bool("x", false, "show end-to-end encryption key")
	zflag := flag.Bool("z", false, "run forever")
	qflag := flag.Bool("q", false, "quick setup")
	flag.Parse()
	verbose := *vflag
	configure := *cflag
	initialize := *iflag
	useFile := *fflag
	importServerKeys := *kflag
	showServerKeys := *jflag
	showConfig := *sflag
	adminMode := *aflag
	generateEndToEndKeys := *gflag
	importEndToEndKeys := *eflag
	showEndToEndKeys := *xflag
	runForever := *zflag
	quickSetup := *qflag
	if verbose {
		fmt.Println("same version 0.5.8")
		fmt.Println("Command line flags:")
		fmt.Println("    Initialize mode:", onOff(initialize))
		fmt.Println("    Configure mode:", onOff(configure))
		fmt.Println("    Import server key mode:", onOff(importServerKeys))
		fmt.Println("    Show server key:", onOff(showServerKeys))
		fmt.Println("    Admin mode:", onOff(adminMode))
		fmt.Println("    Use database file (manual override):", useFile)
		fmt.Println("    Generate End-To-End encryption keys:", onOff(generateEndToEndKeys))
		fmt.Println("    Run forever:", onOff(runForever))
	}
	if quickSetup {
		doQuickSetup(verbose, currentPath, databaseFileName, useFile)
		return
	}
	rootPath := ""
	var db *sql.DB
	if initialize {
		db, err = checkForNestingAndInitializeDB(verbose, rootPath, currentPath, useFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Println("Initialized.")
		return
	} else {
		rootPath, db, err = getStateDB(currentPath, useFile, databaseFileName, verbose)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
	defer db.Close()
	if importServerKeys {
		keyboard := bufio.NewReader(os.Stdin)
		fmt.Print("Server key: ")
		keyLine := getLine(keyboard)
		if len(keyLine) != 128 {
			fmt.Fprintln(os.Stderr, "Key is of wrong length.")
			return
		}
		keysAllBytes, err := hex.DecodeString(keyLine)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Key is not in hexadecimal format.")
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("Key entered:", hex.EncodeToString(keysAllBytes))
		}
		symkey := make([]byte, 32)
		hmackey := make([]byte, 32)
		copy(symkey, keysAllBytes[:32])
		copy(hmackey, keysAllBytes[32:])
		samecommon.SetNameValuePair(db, "serversymkey", hex.EncodeToString(symkey))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("serversymkey set to", hex.EncodeToString(symkey))
		}
		samecommon.SetNameValuePair(db, "serverhmackey", hex.EncodeToString(hmackey))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("serverhmackey set to", hex.EncodeToString(hmackey))
		}
		return
	}
	if showServerKeys {
		symmetricKeyStr := getValue(db, "serversymkey", "")
		hmacKeyStr := getValue(db, "serverhmackey", "")
		fmt.Print(symmetricKeyStr)
		fmt.Println(hmacKeyStr)
		return
	}
	if configure {
		fmt.Println("Any entry you leave blank will not be updated.")
		// server := ""
		fmt.Print("Server: ")
		keyboard := bufio.NewReader(os.Stdin)
		server := getLine(keyboard)
		if server != "" {
			samecommon.SetNameValuePair(db, "server", server)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			if verbose {
				fmt.Println("server set to", server)
			}
		}
		port := 0
		fmt.Print("Port: ")
		ptStr := getLine(keyboard)
		if ptStr != "" {
			port = strToInt(ptStr)
			if port != 0 {
				samecommon.SetNameValuePair(db, "port", intToStr(port))
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return
				}
				if verbose {
					fmt.Println("port set to", intToStr(port))
				}
			}
		}
		fmt.Print("Username (email): ")
		username := getLine(keyboard)
		if username != "" {
			samecommon.SetNameValuePair(db, "username", username)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			if verbose {
				fmt.Println("username set to", username)
			}
		}
		fmt.Print("Password: ")
		password := getLine(keyboard)
		if password != "" {
			samecommon.SetNameValuePair(db, "password", password)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			if verbose {
				fmt.Println("password set to", password)
			}
		}
		fmt.Print("Sync point ID: ")
		syncPointID := getLine(keyboard)
		if syncPointID != "" {
			samecommon.SetNameValuePair(db, "syncpointid", syncPointID)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			if verbose {
				fmt.Println("syncpointid", syncPointID)
			}
		}
		return
	}
	if showConfig {
		showConfiguration(db, verbose)
		return
	}
	if generateEndToEndKeys {
		endToEndSymBin, err := samecommon.GenerateAESKey()
		checkError(err)
		endToEndSymKeyStr := hex.EncodeToString(endToEndSymBin)
		endToEndHmacBin, err := samecommon.GenerateAESKey()
		checkError(err)
		endToEndHmacKeyStr := hex.EncodeToString(endToEndHmacBin)
		endToEndIvBin, err := samecommon.GenerateAESInitializationVector()
		checkError(err)
		endToEndIvStr := hex.EncodeToString(endToEndIvBin)
		samecommon.SetNameValuePair(db, "endtoendsymkey", endToEndSymKeyStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("endtoendsymkey set to", endToEndSymKeyStr)
		}
		samecommon.SetNameValuePair(db, "endtoendhmackey", endToEndHmacKeyStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("endtoendhmackey set to", endToEndHmacKeyStr)
		}
		samecommon.SetNameValuePair(db, "endtoendinitializationvector", endToEndIvStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("endtoendinitializationvector set to", endToEndIvStr)
		}
		fmt.Print("End-to-end key: ")
		fmt.Print(endToEndSymKeyStr)
		fmt.Print(endToEndHmacKeyStr)
		fmt.Println(endToEndIvStr)
		return
	}
	if importEndToEndKeys {
		keyboard := bufio.NewReader(os.Stdin)
		fmt.Print("End-to-end key: ")
		keyLine := getLine(keyboard)
		if len(keyLine) != 160 {
			fmt.Fprintln(os.Stderr, "Key is of wrong length.")
			return
		}
		keysAllBytes, err := hex.DecodeString(keyLine)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Key is not in hexadecimal format.")
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("Key entered:", hex.EncodeToString(keysAllBytes))
		}
		endToEndSymKey := make([]byte, 32)
		endToEndHmacKey := make([]byte, 32)
		endToEndIV := make([]byte, 16)
		copy(endToEndSymKey, keysAllBytes[:32])
		copy(endToEndHmacKey, keysAllBytes[32:64])
		copy(endToEndIV, keysAllBytes[64:])
		samecommon.SetNameValuePair(db, "endtoendsymkey", hex.EncodeToString(endToEndSymKey))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("endtoendsymkey set to", hex.EncodeToString(endToEndSymKey))
		}
		samecommon.SetNameValuePair(db, "endtoendhmackey", hex.EncodeToString(endToEndHmacKey))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("endtoendhmackey set to", hex.EncodeToString(endToEndHmacKey))
		}
		samecommon.SetNameValuePair(db, "endtoendinitializationvector", hex.EncodeToString(endToEndIV))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("endtoendinitializationvector set to", hex.EncodeToString(endToEndIV))
		}
		return
	}
	if showEndToEndKeys {
		endToEndSymKeyStr := getValue(db, "endtoendsymkey", "")
		endToEndHmacKeyStr := getValue(db, "endtoendhmackey", "")
		fmt.Println(endToEndSymKeyStr)
		fmt.Println(endToEndHmacKeyStr)
		return
	}
	//
	// ok, if we got here, we're not doing configuration! We're
	// transferring files!!
	// Brrrp! Unless we're going into Admin Mode
	server := getValue(db, "server", "")
	if verbose {
		fmt.Println("Server:", server)
	}
	ptStr := getValue(db, "port", "0")
	port := strToInt(ptStr)
	if verbose {
		fmt.Println("Port:", port)
	}
	username := getValue(db, "username", "")
	if verbose {
		fmt.Println("Username (email):", username)
	}
	password := getValue(db, "password", "")
	if verbose {
		fmt.Println("Password:", password)
	}
	syncPointID := getValue(db, "syncpointid", "")
	if verbose {
		fmt.Println("Sync point ID:", syncPointID)
	}
	endToEndSymKeyStr := getValue(db, "endtoendsymkey", "")
	if verbose {
		fmt.Println("End-to-end symmetric key:", endToEndSymKeyStr)
	}
	endToEndHmacKeyStr := getValue(db, "endtoendhmackey", "")
	if verbose {
		fmt.Println("End-to-end keyed-hash message authentication code key:", endToEndHmacKeyStr)
	}
	if (server == "") || (port == 0) || (username == "") || (password == "") || (syncPointID == "") {
		fmt.Println("Server and sync point information is not set up.")
		fmt.Println("Use same -c to configure.")
		fmt.Println("Use same -s to show current configuration.")
		return
	}
	serverSymKeyStr := getValue(db, "serversymkey", "")
	serverSymKey, err := hex.DecodeString(serverSymKeyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	serverHmacKeyStr := getValue(db, "serverhmackey", "")
	serverHmacKey, err := hex.DecodeString(serverHmacKeyStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	if (len(serverSymKey) == 0) || (len(serverHmacKey) == 0) {
		fmt.Println("Server key is not set up.")
		fmt.Println("Use samed -k on the server to export the key. Use samed -g if you need to generate a key.")
		fmt.Println("Use same -k to import the key here.")
		fmt.Println("Use same -j here if you need to see what the server key set here is.")
		return
	}
	endToEndEncryption := false
	var endToEndIV []byte
	var endToEndSymKey []byte
	var endToEndHmacKey []byte
	endToEndSymKeyStr = getValue(db, "endtoendsymkey", "")
	if endToEndSymKeyStr != "" {
		endToEndSymKey, err = hex.DecodeString(endToEndSymKeyStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		endToEndHmacKeyStr = getValue(db, "endtoendhmackey", "")
		endToEndHmacKey, err = hex.DecodeString(endToEndHmacKeyStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		endToEndIvStr := getValue(db, "endtoendinitializationvector", "")
		endToEndIV, err = hex.DecodeString(endToEndIvStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		endToEndEncryption = true
	}
	keepRunning := true
	for keepRunning {
		wnet, err := openConnection(serverSymKey, serverHmacKey, server, port)
		defer wnet.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if adminMode {
				// We are allowed to use the admin mode even if we can't connect to the server.
				// But we give it "nil" for wnet so it knows we're not connected.
				doAdminMode(nil, db, rootPath, verbose)
			}
			return
		}
		if verbose {
			fmt.Println("Connected to server.")
		}
		if adminMode {
			doAdminMode(wnet, db, rootPath, verbose)
			return
		}
		serverTimeOffset, err := getServerTimeOffset(wnet)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if verbose {
			fmt.Println("Difference between server time and local time:", serverTimeOffset, "nanoseconds")
		}
		// sendFile("/Users/waynerad/Documents/flushdns.txt", wnet, serverTimeOffset)
		err = rpcLogin(wnet, username, password)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Login failed:", err)
			return
		}
		if verbose {
			fmt.Println("Log in as", username, "successful")
			fmt.Println("Scanning local disk")
		}
		// Ok, now that we're logged in, let's scan the local disk and ask the remote server to tell us what it has
		var sortSlice fileSortSlice
		localTree := make([]samecommon.SameFileInfo, 0)
		path := rootPath
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
		putTreeInTableAndFillInHashesThatNeedToBeUpdated(verbose, db, localTree, basePath)
		//
		// At this point, we have to throw away our tree and get a new
		// one from the DB because otherwise we have a tree without
		// deleted files. We have to track the deleted files because
		// otherwise when a user deletes a file, it will just magically
		// reappear every time
		localTree = retrieveTreeFromDB(verbose, db)
		sortSlice.theSlice = localTree
		sort.Sort(&sortSlice)
		remoteTree, err := rpcGetServerTreeForSyncPoint(wnet, syncPointID)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if endToEndEncryption {
			// If end-to-end encryption is turned on, we need to
			// decrypt the file names before we pass them into
			// synchronizeTrees -- it would be seriously inconvenient
			// to decrypt them there. We also need to sort them since
			// the sort order of the encrypted version of the file
			// names -- which is the order they're sorted on the server
			// -- will be completely different from the order they're
			// sorted into once they've been decrypted.
			lremote := len(remoteTree)
			for ii := 0; ii < lremote; ii++ {
				remoteTree[ii].FilePath, err = decryptDirectoryPath(remoteTree[ii].FilePath, endToEndIV, endToEndSymKey, endToEndHmacKey)
			}
		}
		sortSlice.theSlice = remoteTree
		sort.Sort(&sortSlice)
		if !endToEndEncryption {
			fmt.Println("End-to-end encryption is not set up. Use same -e to import an end-to-end")
			fmt.Println("encryption key. If you do not have an end-to-end encryption key, use same -g to")
			fmt.Println("generate one.")
			return
		}
		synchronizeTrees(verbose, db, wnet, syncPointID, path, localTree, "", remoteTree, serverTimeOffset, runForever, endToEndEncryption, endToEndIV, endToEndSymKey, endToEndHmacKey)
		keepRunning = false
		if runForever {
			wnet.Close()
			time.Sleep(time.Second * 512)
			keepRunning = true
		}
	}
}
