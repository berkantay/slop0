package rules

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type EntryPointDetector struct{}

type EntryPoint struct {
	Kind    string // http, grpc, cli, cron, mq
	Route   string // e.g. "POST /users", "grpc UserService", "cli serve"
	Handler string // qualified function name
	File    string
	Line    int
}

func (d *EntryPointDetector) Detect(domainPkgs []domain.Package) ([]domain.EntryPoint, error) {
	lr, err := loadPackagesForAnalysis(domainPkgs,
		packages.NeedName|packages.NeedFiles|packages.NeedSyntax|
			packages.NeedTypes|packages.NeedTypesInfo|packages.NeedImports)
	if err != nil {
		return nil, err
	}

	var entries []domain.EntryPoint
	for _, pkg := range lr.Pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		entries = append(entries, detectEntryPointsInPkg(pkg, lr.Fset)...)
	}
	return entries, nil
}

func detectEntryPointsInPkg(pkg *packages.Package, fset *token.FileSet) []domain.EntryPoint {
	var entries []domain.EntryPoint
	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ep := classifyCall(call, pkg, fset, fname); ep != nil {
				entries = append(entries, *ep)
			}
			return true
		})
	}
	return entries
}

func classifyCall(call *ast.CallExpr, pkg *packages.Package, fset *token.FileSet, fname string) *domain.EntryPoint {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	recvType := resolveExprType(sel.X, pkg.TypesInfo)
	if recvType == "" {
		return nil
	}

	cc := callContext{
		recvType:   recvType,
		methodName: sel.Sel.Name,
		call:       call,
		info:       pkg.TypesInfo,
		fname:      fname,
		pos:        fset.Position(call.Pos()),
	}

	classifiers := []func(callContext) *domain.EntryPoint{
		classifyHTTPCall, classifyGRPCCall, classifyMQCall, classifyCronCall,
	}
	for _, classify := range classifiers {
		if ep := classify(cc); ep != nil {
			return ep
		}
	}
	return nil
}

type callContext struct {
	recvType   string
	methodName string
	call       *ast.CallExpr
	info       *types.Info
	fname      string
	pos        token.Position
}

func (cc callContext) entryPoint(kind, route, handler string) *domain.EntryPoint {
	return &domain.EntryPoint{Kind: kind, Route: route, Handler: handler, File: cc.fname, Line: cc.pos.Line}
}

func classifyHTTPCall(cc callContext) *domain.EntryPoint {
	if !isHTTPRouterType(cc.recvType) || !isRouteMethod(cc.methodName) {
		return nil
	}
	return cc.entryPoint("http", extractHTTPRoute(cc.methodName, cc.call), extractHandlerName(cc.call, cc.info))
}

func classifyGRPCCall(cc callContext) *domain.EntryPoint {
	if !isGRPCServerType(cc.recvType) || !strings.HasPrefix(cc.methodName, "Register") {
		return nil
	}
	svcName := strings.TrimSuffix(strings.TrimPrefix(cc.methodName, "Register"), "Server")
	return cc.entryPoint("grpc", "grpc "+svcName, extractArgName(cc.call, 1, cc.info))
}

func classifyMQCall(cc callContext) *domain.EntryPoint {
	if !isMQConsumerMethod(cc.recvType, cc.methodName) {
		return nil
	}
	return cc.entryPoint("mq", "consume "+extractStringArg(cc.call, 0), extractHandlerName(cc.call, cc.info))
}

func classifyCronCall(cc callContext) *domain.EntryPoint {
	if !isCronType(cc.recvType) || (cc.methodName != "AddFunc" && cc.methodName != "AddJob") {
		return nil
	}
	return cc.entryPoint("cron", "cron "+extractStringArg(cc.call, 0), extractHandlerName(cc.call, cc.info))
}

func resolveExprType(expr ast.Expr, info *types.Info) string {
	tv, ok := info.Types[expr]
	if !ok {
		return ""
	}
	return tv.Type.String()
}

func isHTTPRouterType(typeName string) bool {
	routerTypes := []string{
		"*net/http.ServeMux",
		"*github.com/go-chi/chi", "*github.com/go-chi/chi/v5",
		"*github.com/gin-gonic/gin.Engine", "*github.com/gin-gonic/gin.RouterGroup",
		"*github.com/labstack/echo", "*github.com/labstack/echo/v4",
		"*github.com/gofiber/fiber", "*github.com/gofiber/fiber/v2",
		"*github.com/gorilla/mux.Router",
	}
	for _, rt := range routerTypes {
		if strings.Contains(typeName, strings.TrimPrefix(rt, "*")) {
			return true
		}
	}
	return false
}

func isRouteMethod(name string) bool {
	methods := map[string]bool{
		"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true,
		"Head": true, "Options": true, "Handle": true, "HandleFunc": true,
		"Method": true, "Connect": true, "Trace": true, "Any": true,
		"Group": true, "Route": true, "Mount": true,
	}
	return methods[name]
}

func isGRPCServerType(typeName string) bool {
	return strings.Contains(typeName, "grpc.Server") || strings.Contains(typeName, "grpc.ServiceRegistrar")
}

func isMQConsumerMethod(typeName, method string) bool {
	consumerMethods := map[string]bool{
		"Subscribe": true, "QueueSubscribe": true, "Consume": true,
		"ConsumePartition": true, "ChanSubscribe": true,
	}
	if !consumerMethods[method] {
		return false
	}
	return strings.Contains(typeName, "nats") || strings.Contains(typeName, "sarama") ||
		strings.Contains(typeName, "amqp") || strings.Contains(typeName, "kafka")
}

func isCronType(typeName string) bool {
	return strings.Contains(typeName, "cron.Cron") || strings.Contains(typeName, "scheduler")
}

func extractHTTPRoute(method string, call *ast.CallExpr) string {
	httpMethod := strings.ToUpper(method)
	switch method {
	case "HandleFunc", "Handle":
		httpMethod = "ALL"
	case "Group", "Route", "Mount":
		httpMethod = "GROUP"
	}

	pattern := extractStringArg(call, 0)
	return httpMethod + " " + pattern
}

func extractStringArg(call *ast.CallExpr, idx int) string {
	if idx >= len(call.Args) {
		return "?"
	}
	lit, ok := call.Args[idx].(*ast.BasicLit)
	if !ok {
		return "?"
	}
	return strings.Trim(lit.Value, `"`)
}

func extractHandlerName(call *ast.CallExpr, info *types.Info) string {
	if len(call.Args) == 0 {
		return "?"
	}
	last := call.Args[len(call.Args)-1]
	return exprToName(last, info)
}

func extractArgName(call *ast.CallExpr, idx int, info *types.Info) string {
	if idx >= len(call.Args) {
		return "?"
	}
	return exprToName(call.Args[idx], info)
}

func exprToName(expr ast.Expr, info *types.Info) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if obj, ok := info.Uses[e]; ok {
			if obj.Pkg() != nil {
				return obj.Pkg().Name() + "." + obj.Name()
			}
			return obj.Name()
		}
		return e.Name
	case *ast.SelectorExpr:
		return exprToName(e.X, info) + "." + e.Sel.Name
	case *ast.CallExpr:
		return exprToName(e.Fun, info) + "()"
	case *ast.FuncLit:
		return "func literal"
	case *ast.UnaryExpr:
		return exprToName(e.X, info)
	}
	return "?"
}

func (d *EntryPointDetector) DetectFromLoaded(pkgs []*packages.Package, fset *token.FileSet) []domain.EntryPoint {
	var entries []domain.EntryPoint
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		entries = append(entries, detectEntryPointsInPkg(pkg, fset)...)
	}
	return entries
}
