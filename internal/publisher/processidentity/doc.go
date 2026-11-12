// package processidentity binds one deployed publisher process to its signed
// identity and control lease. group and installed-job loops call Renew and Stop;
// this package starts no worker and owns no application publication or socket.
package processidentity
