// package ingresspool names the public ingress-address placement boundary.
// control and ingress share this value; neither role imports the other.
package pool

type ID string

const PrimaryID ID = "ingress-a"
