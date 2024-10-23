import ipaddress
import re
from lark import Lark


# Definisci la grammatica
received = """
    start: received
    received: "Received:" token* ";" date_time CRLF

    token: word | angle_addr | addr_spec | domain
    date_time: [day_of_week "," ] date time [cfws]
    CRLF: CR LF
    CR: "\\x0d"
    LF: "\\x0a"

    word: atom | quoted_str
    angle_addr: ([cfws] "<" addr_spec ">" [cfws]) | obs_angle_addr
    addr_spec: local_part "@" domain
    domain: dot_atom | domain_literal | obs_domain
    day_of_week: ([fws] DAY_NAME) | obs_day_of_week
    date: day MONTH year
    time: time_of_day zone
    cfws: (([cfws] comment)+ [fws]) | fws

    atom: [cfws] (atext)+ [cfws]
    quoted_str: [cfws] DQUOTE ([fws] qcontent)* [fws] DQUOTE [cfws]
    obs_angle_addr: [cfws] "<" obs_domain_list addr_spec ">" [cfws]
    local_part: dot_atom | quoted_str | obs_local_part
    domain_literal: [cfws] "[" *([fws] dtext) [fws] "]" [cfws]
    obs_domain: atom ("." atom)*
    dot_atom: [cfws] dot_atom_text [cfws]
    obs_day_of_week: [cfws] DAY_NAME [cfws]
    DAY_NAME: "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
    fws: ( [wsp* CRLF] wsp+ ) | obs_fws
    day: ([fws] DIGIT [DIGIT] fws) | obs_day
    MONTH: "Jan" | "Feb" | "Mar" | "Apr" | "May" | "Jun" | "Jul" | "Aug" | "Sep" | "Oct" | "Nov" | "Dec"
    year: (fws DIGIT DIGIT DIGIT DIGIT fws) | obs_year
    time_of_day: hour ":" minute [ ":" second ]
    zone: (fws ("+" | "-") DIGIT DIGIT DIGIT DIGIT) | OBS_ZONE
    comment: "(" [fws] ccontent* [fws] ")"

    atext: ALPHA | DIGIT | NOT_SPECIAL_CHARS
    qcontent: qtext | quoted_pair
    DQUOTE: "\\x22"
    obs_domain_list: (cfws | ",")* "@" domain ("," [cfws] ["@" domain])*
    obs_local_part: word ("." word)*
    dtext: PRINTABLE_WO_SQUARE_BACKSLASH | obs_dtext
    dot_atom_text: atext+ ("." atext+)*
    obs_fws: wsp+ (CRLF wsp+)*
    wsp: SP | HTAB
    
    %import common.DIGIT -> DIGIT
    obs_day: [cfws] DIGIT [DIGIT] [cfws]
    obs_year: [cfws] DIGIT DIGIT  [cfws]
    second: DIGIT DIGIT  | obs_second
    hour: DIGIT DIGIT  | obs_hour
    minute: DIGIT DIGIT  | obs_minute
    OBS_ZONE: "UT" | "GMT" | "EST" | "EDT" | "CST" | "CDT" | "MST" | "MDT" | "PST" | "PDT"
    ccontent: CTEXT | quoted_pair | comment
    %import common.LETTER -> ALPHA
    NOT_SPECIAL_CHARS: /[!#$%&'*+\/=?^_`{|}~]/
    quoted_pair: "\\x5c" (VCHAR | wsp) | obs_quoted_pair
    qtext: /[!-#\x25-\x5B\x5D-\x7E]/ | OBS_NO_WS_CTL
    PRINTABLE_WO_SQUARE_BACKSLASH: /[ !#-~&&[^[]\\]]+/
    obs_dtext: OBS_NO_WS_CTL | quoted_pair 

    SP: "\\x20"
    HTAB: "\\x09"
    obs_second: [cfws] DIGIT DIGIT  [cfws]
    obs_hour: [cfws] DIGIT DIGIT  [cfws]
    obs_minute: [cfws] DIGIT DIGIT  [cfws]
    CTEXT: SP | /[!-\'*-+,-.\/0-9:;=<=>?@[A-Za-z\]_^`{|}~]/
    obs_quoted_pair: "\\x5c" (DX | OBS_NO_WS_CTL | CR | LF)
    VCHAR: SP | /[!-~]/

    OBS_NO_WS_CTL: DX | /[\x01-\x08\x0B\x0C\x0E-\x1F]/
    DX: "\\x00"  
"""
    

test= """
    start: "miao" CRLF
    CRLF: CR LF SP
    CR: "\\x0d"
    LF: "\\x0a"
    SP: "\\x09"

"""

# Parser per la grammatica
#received_parser = Lark(received, parser='earley', regex=True, ambiguity='explicit')
#received_parser = Lark(test, parser='lalr', debug=True, regex=True, strict=True)
# Funzione per validare e interpretare la stringa
# def is_valid_received(expression)->bool:
    
#     try:
#         parse_tree = received_parser.parse(expression)
#         #parse_tree = parser.parse(expression)
#         print(parse_tree.pretty())
#         return True
#     except Exception as e:
#         return False

#GRAMMAR BLOCKS

# Quoted characters RFC5322 (Section 3.2.1)
dquote = r'["]'
obs_qp = r'\\[\x00\x01-\x08\x0A\x0B\x0C\x0D\x0E-\x1F\x7F]'
quoted_pair=rf'(\\[ -~\t]|{obs_qp})'
qtext = r'[!#\$%&\'()*+,\-./0-9:;<=>?@A-Z^_`a-z{|}~]'
qcontent = rf'({qtext}|{quoted_pair})'
#cfws=r'' # for circular dependencies
#fws=r'' # for circular dependencies


#Folding white space and comments RFC5322 (Section 3.2.2)
wsp = r'[ \t]'
crlf = r'\r\n'
fws = rf'(({wsp})*{crlf})?({wsp})+'  # Folding White Space (FWS)
ctext = r'[\x21-\x27\x2A-\x5B\x5D-\x7E]'  # Printable US-ASCII without "(", ")", or "\"

#ccontent=r'' # to resolve circolar dependency
ccontent = rf'({ctext}|{quoted_pair})'
comment= rf'\((({fws})?{ccontent})*{fws}\)'
cfws= rf'((({fws})?{comment})+({fws})?|{fws})'

quoted_string = rf'({cfws})?{dquote}(({fws})?{qcontent})*({fws})?{dquote}'

# Atom RFC5322 (Section 3.2.3)
atext = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
atom = rf'({cfws})?({atext})+{cfws}'
dot_atom_text = rf'({atext})+(\.({atext})+)'
dot_atom=rf'({cfws})+{dot_atom_text}{cfws}'
specials = r'[\(\)<>\[\]:;@\\,."]'




def extract_client_ip(received_spf_header)->(ipaddress.IPv4Address | ipaddress.IPv6Address | None):
    client_ip_pattern = r'client-ip=([0-9a-fA-F:.]+);?'
    
    # Ricerca dell'indirizzo IP nel campo Received-SPF
    match = re.search(client_ip_pattern, received_spf_header)
    if match:
        ip_str = match.group(1)
        try:
            # Verifica se l'indirizzo IP è valido sia in IPv4 che in IPv6
            ipaddress.ip_address(ip_str)
            return ip_str
        except ValueError:
            return None
    return None


def validate_received_spf_header_RFC7208(header: str, just_value: bool = True) -> bool:
    # Define patterns based on the RFC 7208 specification
    result = r'(pass|fail|softfail|neutral|none|temperror|permerror)'
    name = r'[A-Za-z][A-Za-z0-9\-_\.]*'
    # key-value pair pattern
    key= (
        rf'(client-ip|envelope-from|helo|problem|receiver|identity|mechanism|{name})'
    )

    key_value_pair = rf'{key}({cfws})?\=({dot_atom}|{quoted_string})'
    key_value_list = rf'{key_value_pair}(;({cfws})?{key_value_pair})*(;)?'



    # Full header pattern construction
    if just_value:
        header_pattern = (
            rf'^{result}'                
            rf'{fws}'               
            rf'({comment}{fws})?'           
            rf'({key_value_list})?'                
            r'\s*$' 
        )
    else:
        header_pattern = (
            rf'^Received-SPF:{cfws}?'
            rf'{result}'                
            rf'{fws}'               
            rf'({comment}{fws})?'           
            rf'({key_value_list})?'                
            r'\s*$' 
        )

    # Perform the match
    return re.match(header_pattern, header) is not None

spf = "pass (google.com: domain of 31_iiza0jdxakwzzwoansbwtuuaowz.qcakwzzwoansbwtuuaowz.qca@calendar-server.bounces.google.com designates 209.85.220.73 as permitted sender) client-ip=209.85.220.73;"

print(validate_received_spf_header_RFC7208(spf))