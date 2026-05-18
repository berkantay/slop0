package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
	nextID atomic.Int64

	pending   map[int64]chan json.RawMessage
	pendingMu sync.Mutex
	done      chan struct{}
}

type jsonrpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int64      `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *int64           `json:"id,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *jsonrpcError    `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewClient(command string, args ...string) (*Client, error) {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", command, err)
	}

	c := &Client{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  bufio.NewReaderSize(stdout, 1024*1024),
		pending: make(map[int64]chan json.RawMessage),
		done:    make(chan struct{}),
	}

	go c.readLoop()

	return c, nil
}

func (c *Client) readLoop() {
	defer close(c.done)
	for {
		msg, err := c.readMessage()
		if err != nil {
			return
		}

		var resp jsonrpcResponse
		if err := json.Unmarshal(msg, &resp); err != nil {
			continue
		}

		c.dispatchResponse(&resp)
	}
}

func (c *Client) dispatchResponse(resp *jsonrpcResponse) {
	if resp.ID == nil {
		return
	}

	c.pendingMu.Lock()
	ch, ok := c.pending[*resp.ID]
	if ok {
		delete(c.pending, *resp.ID)
	}
	c.pendingMu.Unlock()

	if !ok {
		return
	}

	if resp.Error != nil {
		ch <- nil
	} else {
		ch <- resp.Result
	}
}

func (c *Client) readMessage() ([]byte, error) {
	contentLength := -1
	for {
		line, err := c.stdout.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Content-Length:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:"))
			contentLength, err = strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("bad content-length: %w", err)
			}
		}
	}

	if contentLength < 0 {
		return nil, fmt.Errorf("missing Content-Length header")
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(c.stdout, body); err != nil {
		return nil, err
	}

	return body, nil
}

func (c *Client) Call(method string, params interface{}, result interface{}) error {
	id := c.nextID.Add(1)

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  method,
		Params:  params,
	}

	ch := make(chan json.RawMessage, 1)
	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()

	if err := c.send(req); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return err
	}

	raw := <-ch
	if raw == nil {
		return fmt.Errorf("LSP error for %s", method)
	}

	if result != nil {
		return json.Unmarshal(raw, result)
	}
	return nil
}

func (c *Client) Notify(method string, params interface{}) error {
	req := jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	return c.send(req)
}

func (c *Client) send(req jsonrpcRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := io.WriteString(c.stdin, header); err != nil {
		return err
	}
	if _, err := c.stdin.Write(body); err != nil {
		return err
	}
	return nil
}

func (c *Client) Close() error {
	c.Notify("shutdown", nil)
	c.Notify("exit", nil)
	c.stdin.Close()
	return c.cmd.Wait()
}

func (c *Client) Initialize(rootURI string) (*InitializeResult, error) {
	params := InitializeParams{
		ProcessID: os.Getpid(),
		RootURI:   rootURI,
		Capabilities: ClientCapabilities{
			TextDocument: TextDocumentClientCapabilities{
				References:     &ReferenceClientCapabilities{DynamicRegistration: false},
				Implementation: &ImplementationClientCapabilities{DynamicRegistration: false},
				Definition:     &DefinitionClientCapabilities{DynamicRegistration: false},
				CallHierarchy:  &CallHierarchyClientCapabilities{DynamicRegistration: false},
			},
		},
	}

	var result InitializeResult
	if err := c.Call("initialize", params, &result); err != nil {
		return nil, err
	}

	if err := c.Notify("initialized", struct{}{}); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) DidOpen(uri, languageID, text string) error {
	return c.Notify("textDocument/didOpen", DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:        uri,
			LanguageID: languageID,
			Version:    1,
			Text:       text,
		},
	})
}

func (c *Client) References(uri string, line, character int) ([]Location, error) {
	params := ReferenceParams{
		TextDocument: TextDocumentIdentifier{URI: uri},
		Position:     Position{Line: line, Character: character},
		Context:      ReferenceContext{IncludeDeclaration: false},
	}
	var result []Location
	if err := c.Call("textDocument/references", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) positionRequest(method, uri string, line, character int, result interface{}) error {
	params := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: uri},
		Position:     Position{Line: line, Character: character},
	}
	return c.Call(method, params, result)
}

func (c *Client) Implementation(uri string, line, character int) ([]Location, error) {
	var result []Location
	err := c.positionRequest("textDocument/implementation", uri, line, character, &result)
	return result, err
}

func (c *Client) PrepareCallHierarchy(uri string, line, character int) ([]CallHierarchyItem, error) {
	var result []CallHierarchyItem
	err := c.positionRequest("textDocument/prepareCallHierarchy", uri, line, character, &result)
	return result, err
}

func (c *Client) IncomingCalls(item CallHierarchyItem) ([]CallHierarchyIncomingCall, error) {
	var result []CallHierarchyIncomingCall
	err := c.Call("callHierarchy/incomingCalls", CallHierarchyIncomingCallsParams{Item: item}, &result)
	return result, err
}

func (c *Client) OutgoingCalls(item CallHierarchyItem) ([]CallHierarchyOutgoingCall, error) {
	var result []CallHierarchyOutgoingCall
	err := c.Call("callHierarchy/outgoingCalls", CallHierarchyOutgoingCallsParams{Item: item}, &result)
	return result, err
}
