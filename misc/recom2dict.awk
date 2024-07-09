# https://stackoverflow.com/questions/73628868/decoding-octal-escape-sequences-with-awk
# modified to convert libFuzzer "Recommended dictionary" valid -dict=file
function oct2dec(oct,   dec) {
    dec =  substr(oct,1,1) * 8 * 8
    dec += substr(oct,2,1) * 8
    dec += substr(oct,3,1)
    return dec
}
function octs2chars(str,        head,tail,oct,dec,char) {
    head = ""
    tail = str
    while ( match(tail,/\\[0-7]{3}/) ) {
        oct  = substr(tail,RSTART+1,RLENGTH-1)
        dec  = oct2dec(oct) # replaced "strtonum(0 oct)"
        char = sprintf("\\x%02x", dec)
        head = head substr(tail,1,RSTART-1) char
        tail = substr(tail,RSTART+RLENGTH)
    }
    return head tail
}
{ sub(/ #[^#].*/,""); print octs2chars($0) }
