package config

var (
	ip   string
	port string
)

func GetIp() string {
	return ip
}
func SetIp(ips string) {
	ip = ips
}
func GetPort() string {
	return port
}
func SetPort(p string) {
	port = p
}
