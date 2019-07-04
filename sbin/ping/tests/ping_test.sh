atf_test_case ping_c3
ping_c3_head() {
	atf_set "descr" "Stop after receiving 3 ECHO_RESPONSE packets"
}
ping_c3_body() {
	atf_check -s exit:0 -o save:std.out -e empty \
		  ping -c 3 localhost
	check_ping_statistics std.out $(atf_get_srcdir)/ping_c3.out
	atf_check -s exit:0 -o save:std.out -e empty \
		  ping -6 -c 3 localhost
	check_ping_statistics std.out $(atf_get_srcdir)/ping6_c3.out
}

atf_init_test_cases() {
	atf_add_test_case ping_c3
}

check_ping_statistics() {
    sed -e 's/0.[0-9]\{3\}//g' -e 's/[1-9][0-9]*.[0-9]\{3\}//g' "$1" >"$1".no_times
    atf_check -s exit:0 diff "$1".no_times "$2"
}
