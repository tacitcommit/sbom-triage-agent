# ./demo.sh 실행을 그대로 녹화한다 (편집 없음).  vhs demo.tape → out/demo.mp4
# 필요: brew install vhs font-d2coding(cask), 실데이터 실행 조건(syft·grype·ANTHROPIC_API_KEY)

Output out/demo.mp4

Set Shell "bash"
Set FontFamily "D2Coding"
Set FontSize 30
Set Width 1920
Set Height 1080
Set Padding 36
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set WaitTimeout 5m

Type "./demo.sh"
Sleep 800ms
Enter
Wait+Screen /이 영상은/
Sleep 6s
