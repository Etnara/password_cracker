# password_cracker

### Attacks:
- Brute Force
- Dictionary

### Hashes:
- MD5
- SHA256
- BCrypt

### Usage
    cargo run --release <'Password Hash'> <Style>
    cargo run --release '5f4dcc3b5aa765d61d8327deb882cf99' dict
    cargo run --release '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' brute 
    cargo run --release '$2a$12$YnC9m0PhOQjJekuAClplMefz.EGY09E7TKonJ3Cf4mIzgUCvXlsqG' brute
    
### Requires:
- Cargo
- Visual Studio C++ Build tools

### Dependencies:
- rand = "0.8.4"
- md5 = "0.7.0"
- sha2 = "0.10.6"
- bcrypt = "0.13.0"
