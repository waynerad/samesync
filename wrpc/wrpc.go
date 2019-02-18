package wrpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

type IWNetConnection interface {
	SetDest(target string, port int)
	SetKeys(symmetricKey []byte, hmacKey []byte) error
	Open() error
	EnvelopMessage(message []byte, includeIV bool)
	SendMessage(message []byte) error
	Close()
	DevelopMessage() ([]byte, error)
	DevelopConnectionMessage(conn net.Conn) ([]byte, error)
	NextMessage() ([]byte, error)
	ShoveBytes(plaintext []byte, ciphertext []byte) error
	PullBytes(plaintext []byte, ciphertext []byte) (int, error)
}

type IWRPC interface {
	StartDB(name string, version int, numTables int)
	StartTable(name string, numCols int, numRows int)
	AddColumn(name string, colType int)
	StartRow()
	AddRowColumnInt(param int64) error
	AddRowColumnUint(param uint64) error
	AddRowColumnBool(param bool) error
	AddRowColumnFloat(param float64) error
	AddRowColumnString(param string) error
	AddRowColumnByteArray(param []byte) error
	MarshallDB() error
	SendDB(netConnection IWNetConnection) error
	UnmarshallDB() error
	ReceiveDB(message []byte)
	GetDBName() string
	GetDBVersion() int
	GetNumTables() int
	GetTableName(tblNum int) string
	GetNumCols(tblNum int) int
	GetColName(tblNum int, colNum int) string
	GetColType(tblNum int, colNum int) int
	GetNumRows(tblNum int) int
	GetInt(tblNum int, rowNum int, colNum int) (int64, error)
	GetUint(tblNum int, rowNum int, colNum int) (uint64, error)
	GetBool(tblNum int, rowNum int, colNum int) (bool, error)
	GetFloat(tblNum int, rowNum int, colNum int) (float64, error)
	GetString(tblNum int, rowNum int, colNum int) (string, error)
	GetByteArray(tblNum int, rowNum int, colNum int) ([]byte, error)
}

const ColInt = 1
const ColUint = 2
const ColBool = 3
const ColFloat = 4
const ColString = 5
const ColByteArray = 6

const sentDB = 1
const sentTable = 2

func EncodeUint(ii uint64) []byte {
	var result []byte
	if ii == 0 {
		result = make([]byte, 1)
		result[0] = 0
		return result
	}
	icopy := ii
	numBytes := 1
	var mask uint64
	mask = 255
	icopy -= icopy & mask
	for icopy != 0 {
		numBytes++
		mask <<= 8
		icopy -= icopy & mask
	}
	result = make([]byte, numBytes+1)
	result[0] = byte(numBytes)
	mask = 255
	for xx := 0; xx < numBytes; xx++ {
		value := ii & mask
		result[numBytes-xx] = byte(value)
		ii >>= 8
	}
	return result
}

func DecodeUint(ba []byte) uint64 {
	numBytes := int(ba[0])
	var result uint64
	if numBytes == 0 {
		return 0
	}
	result = uint64(ba[1])
	for ii := 2; ii <= numBytes; ii++ {
		result <<= 8
		result += uint64(ba[ii])
	}
	return result
}

func EncodeInt(ii int64) []byte {
	var result []byte
	if ii == 0 {
		result = make([]byte, 1)
		result[0] = 0
		return result
	}
	if ii > 0 {
		return EncodeUint(uint64(ii))
	}
	result = EncodeUint(uint64(-ii))
	result[0] |= 128 // sign bit
	return result
}

func DecodeInt(ba []byte) int64 {
	numBytes := int(ba[0])
	var result int64
	if numBytes == 0 {
		return 0
	}
	flip := false
	if (numBytes & 128) != 0 {
		// sign bit
		numBytes = numBytes & 127
		flip = true
	}
	result = int64(ba[1])
	for ii := 2; ii <= numBytes; ii++ {
		result <<= 8
		result += int64(ba[ii])
	}
	if flip {
		result = -result
	}
	return result
}

func MakeBlockInt64(ii int64) []byte {
	content := EncodeInt(ii)
	lc := len(content)
	lheader := EncodeInt(int64(lc))
	return append(lheader, content...)
}

func MakeBlockUint64(ii uint64) []byte {
	content := EncodeUint(ii)
	lc := len(content)
	lheader := EncodeInt(int64(lc))
	return append(lheader, content...)
}

func MakeBlockInt(ii int) []byte {
	return MakeBlockInt64(int64(ii))
}

func MakeBlockString(ss string) []byte {
	lc := len(ss)
	if lc == 0 {
		result := make([]byte, 1)
		result[0] = 0
		return result
	}
	lheader := EncodeInt(int64(lc))
	return append(lheader, []byte(ss)...)
}

func MakeBlockFloat(ff float64) []byte {
	content := strconv.FormatFloat(ff, 'g', -1, 64)
	lc := len(content)
	lheader := EncodeInt(int64(lc))
	return append(lheader, []byte(content)...)
}

func MakeBlockByteArray(ba []byte) []byte {
	lc := len(ba)
	lheader := EncodeInt(int64(lc))
	return append(lheader, ba...)
}

// ExtractBlock takes a message and a position of the beginning of the block
// (including header) inside the message and returns the positions of the
// beginning and ending (not inclusive) of the block (*not* including
// the header). The decoding of the contents of the block is the responsibility
// of the caller.
func ExtractBlock(message []byte, offset int) (int, int) {
	var numBytes int
	numBytes = int(message[offset]) // number of bytes in the length header, cannot be negative
	var blockLen int
	blockLen = int(DecodeInt(message[offset:]))
	return offset + 1 + numBytes, offset + 1 + numBytes + blockLen
}

func GetBlockUint(message []byte, offset int) (uint64, int) {
	start, end := ExtractBlock(message, offset)
	uitv := DecodeUint(message[start:end])
	return uitv, end
}

func GetBlockInt64(message []byte, offset int) (int64, int) {
	start, end := ExtractBlock(message, offset)
	itv := DecodeInt(message[start:end])
	return itv, end
}

func GetBlockInt(message []byte, offset int) (int, int) {
	start, end := ExtractBlock(message, offset)
	itv := DecodeInt(message[start:end])
	return int(itv), end
}

func getBlockFloat(message []byte, offset int) (float64, int, error) {
	start, end := ExtractBlock(message, offset)
	fltStr := string(message[start:end])
	fltVal, err := strconv.ParseFloat(fltStr, 64)
	return fltVal, end, err
}

func getBlockString(message []byte, offset int) (string, int) {
	if message[offset] == 0 {
		return "", offset + 1
	}
	start, end := ExtractBlock(message, offset)
	stg := string(message[start:end])
	return stg, end
}

// if using nested blocks, use ExtractBlock() instead of this function
// if using an application-defined data type, use this function
func getBlockByteArray(message []byte, offset int) ([]byte, int) {
	start, end := ExtractBlock(message, offset)
	return message[start:end], end
}

// WNetConnection manages an encrypted network connection
// Handles both encryption (using AES-256) and network transport
// They are integrated on purpose -- never use an unencrypted connection.

type WNetConnection struct {
	target          string
	port            int
	symmetricKey    []byte
	hmacKey         []byte
	ivOutgoing      []byte
	ivSent          bool
	cipherstreamOut cipher.Stream
	netconn         net.Conn
	bitsOnTheWire   []byte
	ivReceived      bool
	ivIncoming      []byte
	cipherstreamIn  cipher.Stream
}

func (self *WNetConnection) SetDest(target string, port int) {
	self.target = target
	self.port = port
}

func (self *WNetConnection) SetKeys(symmetricKey []byte, hmacKey []byte) error {
	self.symmetricKey = symmetricKey
	// HMAC stands for Keyed-Hash Message Authentication Code
	// The HMAC detects alterations of the message as it crosses
	// the network. An attacker can alter the message
	// even if they can't decrypt it.
	self.hmacKey = hmacKey
	block, err := aes.NewCipher(self.symmetricKey)
	if err != nil {
		return err
	}
	//
	// The initialization vector needs to be unique, but not secure.
	// Therefore it's common to include it at the beginning of the
	// ciphertext.
	self.ivOutgoing = make([]byte, aes.BlockSize)
	_, err = rand.Read(self.ivOutgoing)
	if err != nil {
		panic(err)
	}
	self.ivSent = false
	self.cipherstreamOut = cipher.NewOFB(block, self.ivOutgoing)
	return nil
}

func (self *WNetConnection) Open() error {
	var err error
	self.netconn, err = net.Dial("tcp", self.target+":"+intToStr(self.port))
	return err
}

func (self *WNetConnection) EnvelopMessage(message []byte, includeIV bool) {
	hasher := hmac.New(sha256.New, self.hmacKey)

	lx := len(message)

	lenc := EncodeUint(uint64(lx))
	llx := len(lenc)

	// plaintext := []byte("EEEE")
	plaintext := make([]byte, 0, 4+llx+lx)
	plaintext = append(plaintext, []byte("EEEE")...)
	plaintext = append(plaintext, lenc...)
	plaintext = append(plaintext, message...)

	ciphertext := make([]byte, len(plaintext))
	self.cipherstreamOut.XORKeyStream(ciphertext, plaintext)

	hasher.Write(ciphertext)
	signature := hasher.Sum(nil)

	if includeIV {
		self.bitsOnTheWire = make([]byte, len(self.ivOutgoing)+len(ciphertext)+len(signature))
		offset := copy(self.bitsOnTheWire, self.ivOutgoing)
		offset += copy(self.bitsOnTheWire[offset:], ciphertext)
		offset += copy(self.bitsOnTheWire[offset:], signature)
	} else {
		self.bitsOnTheWire = make([]byte, len(ciphertext)+len(signature))
		offset := copy(self.bitsOnTheWire, ciphertext)
		offset += copy(self.bitsOnTheWire[offset:], signature)
	}
}

func (self *WNetConnection) SendMessage(message []byte) error {
	self.EnvelopMessage(message, !self.ivSent)
	lbits := len(self.bitsOnTheWire)
	position := 0
	for position < lbits {
		n, err := self.netconn.Write(self.bitsOnTheWire)
		if err != nil {
			self.netconn.Close()
			return err
		}
		position += n
	}
	self.ivSent = true
	return nil
}

func (self *WNetConnection) Close() {
	self.cipherstreamOut = nil
	if self.netconn != nil {
		self.netconn.Close()
	}
}

func (self *WNetConnection) DevelopMessage() ([]byte, error) {
	// bitsOnTheWire []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	copy(iv, self.bitsOnTheWire)
	block, err := aes.NewCipher(self.symmetricKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, iv)
	llbyte := make([]byte, 5) // EEEE + length byte
	position := aes.BlockSize
	stream.XORKeyStream(llbyte, self.bitsOnTheWire[position:position+5])
	position += 5
	if llbyte[0] != 'E' {
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	if llbyte[1] != 'E' {
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	if llbyte[2] != 'E' {
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	if llbyte[3] != 'E' {
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	lli := int(llbyte[4])
	if lli > 8 {
		return nil, errors.New("llbyte is > 8")
	}
	lbytes := make([]byte, lli)
	stream.XORKeyStream(lbytes, self.bitsOnTheWire[position:position+lli])
	position += lli
	// ok, we have all the length bytes -- now we have to decode
	llTemp := make([]byte, lli+1)
	llTemp[0] = llbyte[4]
	copy(llTemp[1:], lbytes)
	messageLen := int(DecodeUint(llTemp))
	//
	// allocate messageLen bytes to receive the message (+ extra for the signature)
	plaintext := make([]byte, messageLen)
	stream.XORKeyStream(plaintext, self.bitsOnTheWire[position:position+messageLen])
	position += messageLen
	//
	// check the signature
	hasher := hmac.New(sha256.New, self.hmacKey)
	hasher.Write(self.bitsOnTheWire[aes.BlockSize:position])
	expectedMAC := hasher.Sum(nil)
	match := hmac.Equal(self.bitsOnTheWire[position:], expectedMAC)
	if match {
		return plaintext, nil
	}
	return nil, errors.New("Signature check failed.")
}

func (self *WNetConnection) DevelopConnectionMessage(conn net.Conn) ([]byte, error) {
	// This function is the same as DevelopMessage() except instead of
	// having the message all in memory already, it pulls the message
	// in from an open network connection.
	// This function handles the necessary memory allocation to get the
	// ciphertext and plantext in memory and returns the plaintext
	// If the message can't be decoded, it closes the connection! If
	// the message can't be decrypted someone is probably trying to hack us.
	//
	// Function is aggressive about closing connections if anything goes
	// wrong to discourage hackers.
	//
	// step 1: read AES initialization vector

	if !self.ivReceived {
		self.ivIncoming = make([]byte, aes.BlockSize)

		n, err := conn.Read(self.ivIncoming)
		if err != nil {
			if err == io.EOF {
				conn.Close()
				return nil, errors.New("Could not read AES256 initialization vector. Connection closed.")
			}
			conn.Close()
			return nil, err
		}
		if n != 16 {
			conn.Close()
			return nil, errors.New("Could only read partial AES256 initialization vector. Connection closed.")
		}

		block, err := aes.NewCipher(self.symmetricKey)
		if err != nil {
			conn.Close()
			return nil, err
		}
		self.cipherstreamIn = cipher.NewOFB(block, self.ivIncoming)
		self.ivReceived = true
	}

	//
	// step 2: read the EEEE check and length byte
	cipherl1 := make([]byte, 5)

	n, err := conn.Read(cipherl1)
	if err != nil {
		if err == io.EOF {
			conn.Close()
			if n == 0 {
				return nil, errors.New("No message. Connection assumed to be closed on remote end. Connection closed.")
			}
			return nil, errors.New("Could not read ciphertext length bytes. Connection closed.")
		}
		conn.Close()
		return nil, err
	}
	if n != 5 {
		conn.Close()
		return nil, errors.New("Insufficient data for ciphertext length bytes. Connection closed.")
	}

	llbyte := make([]byte, 5) // EEEE + length byte
	self.cipherstreamIn.XORKeyStream(llbyte, cipherl1)
	if llbyte[0] != 'E' {
		conn.Close()
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	if llbyte[1] != 'E' {
		conn.Close()
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	if llbyte[2] != 'E' {
		conn.Close()
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	if llbyte[3] != 'E' {
		conn.Close()
		return nil, errors.New("Length bytes decryption check failed. Connection closed.")
	}
	lli := int(llbyte[4])
	if lli > 8 {
		conn.Close()
		return nil, errors.New("Length bytes too large. Not allocating buffer. Connection closed.")
	}
	cipherl2 := make([]byte, lli)

	n, err = conn.Read(cipherl2)
	if err != nil {
		if err == io.EOF {
			conn.Close()
			return nil, errors.New("Insufficient byte for length bytes. End of message reached. Connection closed.")
		}
		conn.Close()
		return nil, err
	}
	if n != lli {
		conn.Close()
		return nil, errors.New("Insufficient bytes for length bytes. Connection closed.")
	}

	lbytes := make([]byte, lli)
	self.cipherstreamIn.XORKeyStream(lbytes, cipherl2)
	// ok, we have all the length bytes -- now we have to decode
	llTemp := make([]byte, lli+1)
	llTemp[0] = llbyte[4]
	copy(llTemp[1:], lbytes)
	messageLen := int(DecodeUint(llTemp))
	//
	// step 3: allocate messageLen bytes to receive the message (+ extra for the signature)
	ciphertext := make([]byte, 5+lli+messageLen)
	copy(ciphertext, cipherl1)
	copy(ciphertext[5:], cipherl2)
	cpos := 5 + lli
	contentstart := cpos
	n, err = conn.Read(ciphertext[cpos:16])
	if err != nil {
		if err == io.EOF {
			conn.Close()
			return nil, errors.New("Could not read ciphertext into buffer. End of message reached. Connection closed.")
		}
		conn.Close()
		return nil, err
	}
	for n > 0 {
		cpos += n
		n, err = conn.Read(ciphertext[cpos:])
		if err != nil {
			if err == io.EOF {
				conn.Close()
				return nil, errors.New("Could not read ciphertext into buffer. End of message reached. Connection closed.")
			}
			conn.Close()
			return nil, err
		}
	}
	if cpos != (5 + lli + messageLen) {
		conn.Close()
		return nil, errors.New("Not all of the ciphertext of the message was read. Connection closed.")
	}
	plaintext := make([]byte, messageLen)
	self.cipherstreamIn.XORKeyStream(plaintext, ciphertext[contentstart:])
	//
	// step 4: check the signature

	signature := make([]byte, 32)
	n, err = conn.Read(signature)
	if err != nil {
		if err == io.EOF {
			conn.Close()
			return nil, errors.New("Signature could not be read. End of input reached. Connection closed.")
		}
		conn.Close()
		return nil, err
	}
	if n != 32 {
		conn.Close()
		return nil, errors.New("Signature could not be read. Insufficient bytes. Connection closed.")
	}

	hasher := hmac.New(sha256.New, self.hmacKey)
	hasher.Write(ciphertext)
	expectedMAC := hasher.Sum(nil)
	match := hmac.Equal(signature, expectedMAC)
	if match {
		self.netconn = conn
		return plaintext, nil
		// connection is NOT closed!
	}
	conn.Close()
	return nil, errors.New("Signature failed to match. Connection closed.")
}

func (self *WNetConnection) NextMessage() ([]byte, error) {
	return self.DevelopConnectionMessage(self.netconn)
}

func (self *WNetConnection) ShoveBytes(plaintext []byte, ciphertext []byte) error {
	// This function shoves naked bytes into the connection
	// Used for file transfers where the file can be of unlimited size
	// and we don't want chunks of our file wrapped in messages with
	// initialization vectors and signature checks.
	// We leave it to the application to send a hash that checks the
	// integrity of the file transfer.
	// The ciphertext buffer is passed as a parameter so the caller can allocate it once
	// for the entire file, and it doesn't get continuously re-allocated in here
	// The caller shouldn't need (or be able to) inspect the ciphertext, though.
	// It's just a memory allocation optimization.
	if plaintext == nil {
		return errors.New("ShoveBytes: plaintext buffer is not defined.")
	}
	if ciphertext == nil {
		return errors.New("ShoveBytes: ciphertext buffer is not defined.")
	}
	if len(plaintext) != len(ciphertext) {
		return errors.New("ShoveBytes: plaintext and ciphertext buffers are not of equal length")
	}
	self.cipherstreamOut.XORKeyStream(ciphertext, plaintext)
	lbits := len(ciphertext)
	position := 0
	for position < lbits {
		n, err := self.netconn.Write(ciphertext)
		if err != nil {
			self.netconn.Close()
			return err
		}
		position += n
	}
	return nil
}

func (self *WNetConnection) PullBytes(plaintext []byte, ciphertext []byte) (int, error) {
	// PullBytes is the inverse of ShoveBytes, used to pull bytes out
	// that have been shoved in on the other end
	// ciphertext parameter is a memory optimization as described in
	// the comments to ShoveBytes
	if plaintext == nil {
		return 0, errors.New("ShoveBytes: plaintext buffer is not defined.")
	}
	if ciphertext == nil {
		return 0, errors.New("ShoveBytes: ciphertext buffer is not defined.")
	}
	if len(plaintext) != len(ciphertext) {
		return 0, errors.New("ShoveBytes: plaintext and ciphertext buffers are not of equal length")
	}
	numBytes, err := self.netconn.Read(ciphertext)
	if err != nil {
		if err == io.EOF {
			self.netconn.Close()
			return numBytes, errors.New("PullBytes hit the end of the message. Connection closed.")
		}
		self.netconn.Close()
		return numBytes, err
	}
	if numBytes == len(ciphertext) {
		self.cipherstreamIn.XORKeyStream(plaintext, ciphertext)
	} else {
		self.cipherstreamIn.XORKeyStream(plaintext[:numBytes], ciphertext[:numBytes])
	}
	return numBytes, err
}

func intToStr(ii int) string {
	return strconv.FormatInt(int64(ii), 10)
}

func NameOfColType(colType int) string {
	switch colType {
	case ColInt:
		return "int"
	case ColUint:
		return "unsigned int"
	case ColBool:
		return "bool"
	case ColFloat:
		return "float"
	case ColString:
		return "string"
	case ColByteArray:
		return "byte array"
	}
	return ""
}

type columnInfo struct {
	name    string
	colType int
}

type tableInfo struct {
	name    string
	columns []columnInfo
	rows    [][][]byte
}

type XWRPC struct {
	dbname    string
	dbversion int
	tables    []tableInfo
	message   []byte
}

func (self *XWRPC) StartDB(name string, version int, numTables int) {
	self.tables = make([]tableInfo, 0, numTables)
	self.dbname = name
	self.dbversion = version
}

func (self *XWRPC) StartTable(name string, numCols int, numRows int) {
	var newTable tableInfo
	newTable.name = name
	newTable.columns = make([]columnInfo, 0, numCols)
	newTable.rows = make([][][]byte, 0, numRows)
	self.tables = append(self.tables, newTable)
}

func (self *XWRPC) AddColumn(name string, colType int) {
	tblNum := len(self.tables) - 1
	self.tables[tblNum].columns = append(self.tables[tblNum].columns, columnInfo{name, colType})
}

func (self *XWRPC) StartRow() {
	tblNum := len(self.tables) - 1
	numCols := len(self.tables[tblNum].columns)
	newRow := make([][]byte, 0, numCols)
	self.tables[tblNum].rows = append(self.tables[tblNum].rows, newRow)
}

func (self *XWRPC) AddRowColumnInt(param int64) error {
	tblNum := len(self.tables) - 1
	rowNum := len(self.tables[tblNum].rows) - 1
	lc := len(self.tables[tblNum].rows[rowNum])
	if lc >= len(self.tables[tblNum].columns) {
		return errors.New("Attempted to add column value, but there are no more columns.")
	}
	if self.tables[tblNum].columns[lc].colType != ColInt {
		return errors.New("Incorrect type for column. Expected type " + NameOfColType(self.tables[tblNum].columns[lc].colType) + " for column " + `"` + self.tables[tblNum].columns[lc].name + `"` + " but actually got " + NameOfColType(ColInt))
	}
	// we add ints "naked" to save bytes
	self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], EncodeInt(param))
	return nil
}

func (self *XWRPC) AddRowColumnUint(param uint64) error {
	tblNum := len(self.tables) - 1
	rowNum := len(self.tables[tblNum].rows) - 1
	lc := len(self.tables[tblNum].rows[rowNum])
	if lc >= len(self.tables[tblNum].columns) {
		return errors.New("Attempted to add column value, but there are no more columns.")
	}
	if self.tables[tblNum].columns[lc].colType != ColUint {
		return errors.New("Incorrect type for column. Expected type " + NameOfColType(self.tables[tblNum].columns[lc].colType) + " for column " + `"` + self.tables[tblNum].columns[lc].name + `"` + " but actually got " + NameOfColType(ColUint))
	}
	// we add ints "naked" to save bytes
	self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], EncodeUint(param))
	return nil
}

func (self *XWRPC) AddRowColumnBool(param bool) error {
	tblNum := len(self.tables) - 1
	rowNum := len(self.tables[tblNum].rows) - 1
	lc := len(self.tables[tblNum].rows[rowNum])
	if lc >= len(self.tables[tblNum].columns) {
		return errors.New("Attempted to add column value, but there are no more columns.")
	}
	if self.tables[tblNum].columns[lc].colType != ColBool {
		return errors.New("Incorrect type for column. Expected type " + NameOfColType(self.tables[tblNum].columns[lc].colType) + " for column " + `"` + self.tables[tblNum].columns[lc].name + `"` + " but actually got " + NameOfColType(ColBool))
	}
	// we add ints "naked" to save bytes
	var uiParam uint64
	if param {
		uiParam = 1
	} else {
		uiParam = 0
	}
	self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], EncodeUint(uiParam))
	return nil
}

func (self *XWRPC) AddRowColumnFloat(param float64) error {
	tblNum := len(self.tables) - 1
	rowNum := len(self.tables[tblNum].rows) - 1
	lc := len(self.tables[tblNum].rows[rowNum])
	if lc >= len(self.tables[tblNum].columns) {
		return errors.New("Attempted to add column value, but there are no more columns.")
	}
	if self.tables[tblNum].columns[lc].colType != ColFloat {
		return errors.New("Incorrect type for column. Expected type " + NameOfColType(self.tables[tblNum].columns[lc].colType) + " for column " + `"` + self.tables[tblNum].columns[lc].name + `"` + " but actually got " + NameOfColType(ColFloat))
	}
	self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], MakeBlockFloat(param))
	return nil
}

func (self *XWRPC) AddRowColumnString(param string) error {
	tblNum := len(self.tables) - 1
	rowNum := len(self.tables[tblNum].rows) - 1
	lc := len(self.tables[tblNum].rows[rowNum])
	if lc >= len(self.tables[tblNum].columns) {
		return errors.New("Attempted to add column value, but there are no more columns.")
	}
	if self.tables[tblNum].columns[lc].colType != ColString {
		return errors.New("Incorrect type for column. Expected type " + NameOfColType(self.tables[tblNum].columns[lc].colType) + " for column " + `"` + self.tables[tblNum].columns[lc].name + `"` + " but actually got " + NameOfColType(ColString))
	}
	self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], MakeBlockString(param))
	return nil
}

func (self *XWRPC) AddRowColumnByteArray(param []byte) error {
	tblNum := len(self.tables) - 1
	rowNum := len(self.tables[tblNum].rows) - 1
	lc := len(self.tables[tblNum].rows[rowNum])
	if lc >= len(self.tables[tblNum].columns) {
		return errors.New("Attempted to add column value, but there are no more columns.")
	}
	if self.tables[tblNum].columns[lc].colType != ColByteArray {
		return errors.New("Incorrect type for column. Expected type " + NameOfColType(self.tables[tblNum].columns[lc].colType) + " for column " + `"` + self.tables[tblNum].columns[lc].name + `"` + " but actually got " + NameOfColType(ColByteArray))
	}
	self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], MakeBlockByteArray(param))
	return nil
}

func (self *XWRPC) MarshallDB() error {
	self.message = make([]byte, 2, 1024)
	self.message[0] = 'V'
	self.message[1] = 0
	self.message = append(self.message, 'D')
	self.message = append(self.message, MakeBlockString(self.dbname)...)
	self.message = append(self.message, byte(self.dbversion))

	tblCount := len(self.tables)
	for tblNum := 0; tblNum < tblCount; tblNum++ {
		self.message = append(self.message, []byte("T")...)

		self.message = append(self.message, MakeBlockString(self.tables[tblNum].name)...)
		numColumns := len(self.tables[tblNum].columns)
		// self.message = append(self.message, MakeBlockInt(numColumns)...)
		self.message = append(self.message, EncodeInt(int64(numColumns))...)
		numRows := len(self.tables[tblNum].rows)
		// self.message = append(self.message, MakeBlockUint64(uint64(numRows))...)
		self.message = append(self.message, EncodeInt(int64(numRows))...)

		for colNum := 0; colNum < numColumns; colNum++ {
			self.message = append(self.message, MakeBlockString(self.tables[tblNum].columns[colNum].name)...)
			self.message = append(self.message, byte(self.tables[tblNum].columns[colNum].colType))
		}

		for rowNum := 0; rowNum < numRows; rowNum++ {
			if len(self.tables[tblNum].rows[rowNum]) != numColumns {
				return errors.New("Wrong number of columns in row " + intToStr(rowNum) + ". Cannot marshall.")
			}
			for colNum := 0; colNum < numColumns; colNum++ {
				self.message = append(self.message, self.tables[tblNum].rows[rowNum][colNum]...)
			}
		}
	}
	return nil
}

func (self *XWRPC) SendDB(netConnection IWNetConnection) error {
	err := self.MarshallDB()
	if err != nil {
		return err
	}
	return netConnection.SendMessage(self.message)
}

func (self *XWRPC) UnmarshallDB() error {
	position := 0
	dbname := ""
	tablename := ""
	numCols := 0
	colName := ""
	colType := 0
	var colBytes []byte
	numRows := 0
	lm := len(self.message)
	for position < lm {
		thingType := self.message[position]
		switch thingType {
		case 'D':
			position++
			dbname, position = getBlockString(self.message, position)
			self.dbname = dbname
			self.dbversion = int(self.message[position])
			position++
		case 'T':
			position++
			tablename, position = getBlockString(self.message, position)
			// int and uint are sent "naked" to save bytes

			numBytes := int(self.message[position])
			intBytes := self.message[position : position+numBytes+1]
			position += numBytes + 1
			numCols = int(DecodeInt(intBytes))

			numBytes = int(self.message[position])
			intBytes = self.message[position : position+numBytes+1]
			position += numBytes + 1
			numRows = int(DecodeInt(intBytes))

			self.StartTable(tablename, numCols, numRows)
			for colNum := 0; colNum < numCols; colNum++ {
				colName, position = getBlockString(self.message, position)
				colType = int(self.message[position])
				position++
				self.AddColumn(colName, colType)
			}
			tblNum := len(self.tables) - 1
			for rowNum := 0; rowNum < numRows; rowNum++ {
				self.StartRow()
				for colNum := 0; colNum < numCols; colNum++ {
					if position >= len(self.message) {
						return errors.New("Off end of message. Message was malformed on the sending end.")
					}
					// int and uint are sent "naked" to save bytes
					switch self.tables[tblNum].columns[colNum].colType {
					case ColInt:
						intNumBytes := int(self.message[position])
						if (intNumBytes & 128) != 0 {
							// sign bit
							intNumBytes = intNumBytes & 127
						}
						self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], self.message[position:position+intNumBytes+1])
						position += intNumBytes + 1
					case ColUint:
						uIntNumBytes := int(self.message[position])
						self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], self.message[position:position+uIntNumBytes+1])
						position += uIntNumBytes + 1
					case ColBool:
						blNumBytes := int(self.message[position])
						self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], self.message[position:position+blNumBytes+1])
						position += blNumBytes + 1
					default:
						colBytes, position = getBlockByteArray(self.message, position)
						self.tables[tblNum].rows[rowNum] = append(self.tables[tblNum].rows[rowNum], colBytes)
					}
				}
			}
		case 'V':
			// version number
			position++
			if self.message[position] != 0 {
				return errors.New("Version number mismatch (expected 0, got " + intToStr(int(self.message[position])) + ")")
			}
			position++
		default:
			return errors.New("Entry is not a database, table, or row")
		}
	}
	return nil
}

func (self *XWRPC) ReceiveDB(message []byte) {
	self.message = message
	self.UnmarshallDB()
}

func (self *XWRPC) GetDBName() string {
	return self.dbname
}

func (self *XWRPC) GetDBVersion() int {
	return self.dbversion
}

func (self *XWRPC) GetNumTables() int {
	return len(self.tables)
}

func (self *XWRPC) GetTableName(tblNum int) string {
	return self.tables[tblNum].name
}

func (self *XWRPC) GetNumCols(tblNum int) int {
	return len(self.tables[tblNum].columns)
}

func (self *XWRPC) GetColName(tblNum int, colNum int) string {
	return self.tables[tblNum].columns[colNum].name
}

func (self *XWRPC) GetColType(tblNum int, colNum int) int {
	return self.tables[tblNum].columns[colNum].colType
}

func (self *XWRPC) GetNumRows(tblNum int) int {
	return len(self.tables[tblNum].rows)
}

func (self *XWRPC) GetInt(tblNum int, rowNum int, colNum int) (int64, error) {
	if self.tables[tblNum].columns[colNum].colType != ColInt {
		return 0, errors.New("Incorrect type for column. Expected type " + NameOfColType(ColInt) + " but data was actually " + NameOfColType(self.tables[tblNum].columns[colNum].colType))
	}
	theBytes := self.tables[tblNum].rows[rowNum][colNum]
	return DecodeInt(theBytes), nil
}

func (self *XWRPC) GetUint(tblNum int, rowNum int, colNum int) (uint64, error) {
	if self.tables[tblNum].columns[colNum].colType != ColUint {
		return 0, errors.New("Incorrect type for column. Expected type " + NameOfColType(ColUint) + " but data was actually " + NameOfColType(self.tables[tblNum].columns[colNum].colType))
	}
	theBytes := self.tables[tblNum].rows[rowNum][colNum]
	return DecodeUint(theBytes), nil
}

func (self *XWRPC) GetBool(tblNum int, rowNum int, colNum int) (bool, error) {
	if self.tables[tblNum].columns[colNum].colType != ColBool {
		return false, errors.New("Incorrect type for column. Expected type " + NameOfColType(ColBool) + " but data was actually " + NameOfColType(self.tables[tblNum].columns[colNum].colType))
	}
	theBytes := self.tables[tblNum].rows[rowNum][colNum]
	uiVal := DecodeUint(theBytes)
	var bVal bool
	if uiVal == 0 {
		bVal = false
	} else {
		bVal = true
	}
	return bVal, nil
}

func (self *XWRPC) GetFloat(tblNum int, rowNum int, colNum int) (float64, error) {
	if self.tables[tblNum].columns[colNum].colType != ColFloat {
		return 0, errors.New("Incorrect type for column. Expected type " + NameOfColType(ColFloat) + " but data was actually " + NameOfColType(self.tables[tblNum].columns[colNum].colType))
	}
	theBytes := self.tables[tblNum].rows[rowNum][colNum]
	fltStr := string(theBytes)
	fltVal, err := strconv.ParseFloat(fltStr, 64)
	return fltVal, err
}

func (self *XWRPC) GetString(tblNum int, rowNum int, colNum int) (string, error) {
	if self.tables[tblNum].columns[colNum].colType != ColString {
		return "", errors.New("Incorrect type for column. Expected type " + NameOfColType(ColString) + " but data was actually " + NameOfColType(self.tables[tblNum].columns[colNum].colType))
	}
	theBytes := self.tables[tblNum].rows[rowNum][colNum]
	return string(theBytes), nil
}

func (self *XWRPC) GetByteArray(tblNum int, rowNum int, colNum int) ([]byte, error) {
	if self.tables[tblNum].columns[colNum].colType != ColByteArray {
		return nil, errors.New("Incorrect type for column. Expected type " + NameOfColType(ColByteArray) + " but data was actually " + NameOfColType(self.tables[tblNum].columns[colNum].colType))
	}
	theBytes := self.tables[tblNum].rows[rowNum][colNum]
	return theBytes, nil
}

func NewDB() IWRPC {
	var result XWRPC
	return &result
}

func NewConnection() IWNetConnection {
	var result WNetConnection
	return &result
}

// Helper functions to speed things up

func SendReplyScalarInt(funcname string, version int, result int64, errmsg string, wnet IWNetConnection) error {
	var reply XWRPC
	reply.StartDB(funcname+"Reply", version, 1)
	reply.StartTable("", 1, 2)
	reply.AddColumn("", ColInt)
	reply.AddColumn("", ColString)
	reply.StartRow()
	reply.AddRowColumnInt(result)
	reply.AddRowColumnString(errmsg)
	return reply.SendDB(wnet)
}

func SendReplyScalarString(funcname string, version int, result string, errmsg string, wnet IWNetConnection) error {
	var reply XWRPC
	reply.StartDB(funcname+"Reply", version, 1)
	reply.StartTable("", 1, 2)
	reply.AddColumn("", ColString)
	reply.AddColumn("", ColString)
	reply.StartRow()
	reply.AddRowColumnString(result)
	reply.AddRowColumnString(errmsg)
	return reply.SendDB(wnet)
}

func SendReplyVoid(funcname string, version int, errmsg string, wnet IWNetConnection) error {
	var reply XWRPC
	reply.StartDB(funcname+"Reply", version, 1)
	reply.StartTable("", 1, 1)
	reply.AddColumn("", ColString)
	reply.StartRow()
	reply.AddRowColumnString(errmsg)
	return reply.SendDB(wnet)
}

// Helper functions for debugging

func DebugDumpToConsole(rpc IWRPC) {
	fmt.Println("Database name is:", rpc.GetDBName())
	numTables := rpc.GetNumTables()
	fmt.Println("Number of tables:", numTables)
	for tblNum := 0; tblNum < numTables; tblNum++ {
		fmt.Println("Looking at table number:", tblNum)
		fmt.Println("    Name:", rpc.GetTableName(tblNum))
		numCols := rpc.GetNumCols(tblNum)
		fmt.Println("    Number of columns:", numCols)
		for colNum := 0; colNum < numCols; colNum++ {
			fmt.Println("        Column number:", colNum)
			colName := rpc.GetColName(tblNum, colNum)
			fmt.Println("        Column name:", colName)
			colType := rpc.GetColType(tblNum, colNum)
			fmt.Println("        Column Type:", NameOfColType(colType))
		}
		numRows := rpc.GetNumRows(tblNum)
		fmt.Println("    Number of rows:", numRows)
		for rowNum := 0; rowNum < numRows; rowNum++ {
			fmt.Println("        Row number:", rowNum)
			for colNum := 0; colNum < numCols; colNum++ {
				fmt.Print("            Column " + intToStr(colNum) + ": ")
				colName := rpc.GetColName(tblNum, colNum)
				if colName == "" {
					colName = "column value"
				}
				colType := rpc.GetColType(tblNum, colNum)
				switch colType {
				case ColInt:
					ival, err := rpc.GetInt(tblNum, rowNum, colNum)
					if err != nil {
						fmt.Println("Int extract failed in int column")
					}
					fmt.Println(colName+" (int):", ival)
				case ColUint:
					uval, err := rpc.GetUint(tblNum, rowNum, colNum)
					if err != nil {
						fmt.Println("Unsigned int extract in column failed")
					}
					fmt.Println(colName+" (uint):", uval)
				case ColFloat:
					fval, err := rpc.GetFloat(tblNum, rowNum, colNum)
					if err != nil {
						fmt.Println("extract of GetFloat failed on float column")
					}
					fmt.Println(colName+" (float):", fval)
				case ColString:
					sval, err := rpc.GetString(tblNum, rowNum, colNum)
					if err != nil {
						fmt.Println("Extract GetString for column failed")
					}
					fmt.Println(colName + " (string): " + `"` + sval + `"`)
				case ColByteArray:
					bval, err := rpc.GetByteArray(tblNum, rowNum, colNum)
					if err != nil {
						fmt.Println("GetByteArray extraction in column failed")
					}
					fmt.Println(colName+" (byte array):", bval)
				default:
					fmt.Println("Unrecognized column type returned")
				}
			}
		}
	}
	fmt.Println("End of message.")
}
