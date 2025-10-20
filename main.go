package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
)

var lines []string
var fileContent string

func main() {
	filename := "testsite.txt"

	// Создаем файл если не существует
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		file, err := os.Create(filename)
		if err != nil {
			fmt.Printf("Ошибка создания файла: %v\n", err)
			return
		}
		// Записываем тестовые данные в файл
		file.WriteString("Привет, мир!\nЭто тестовый файл\nТретья строка файла")
		file.Close()
		fmt.Println("Файл создан успешно")
	} else {
		fmt.Println("Файл уже существует")
	}

	// Чтение всего файла
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Ошибка чтения: %v\n", err)
		return
	}
	fileContent = string(content)
	fmt.Printf("Переменная content (%d байт) загружена.\n", len(content))

	// Чтение построчно
	lines, err = readLines(filename)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}
	fmt.Printf("Переменная lines содержит %d строк.\n", len(lines))

	// Настройка HTTP маршрутов
	http.HandleFunc("/", siteHandler)

	fmt.Println("Сервер запущен на http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
func siteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Простой HTML вывод
	html := `
<html>
<head><title>Данные файла</title></head>
<body>
    <h1>Содержимое файла testsite.txt</h1>
    
    <h2>Полный текст:</h2>
    <pre>%s</pre>
    
    <h2>Построчно:</h2>
    <ul>
    %s
    </ul>
    
    <p><strong>Всего строк: %d</strong></p>
    <p><strong>Размер: %d байт</strong></p>
</body>
</html>
`

	// Формируем список строк
	linesList := ""
	for i, line := range lines {
		linesList += fmt.Sprintf("<li>Строка %d: %s</li>", i+1, line)
	}

	fmt.Fprintf(w, html, fileContent, linesList, len(lines), len(fileContent))
}
