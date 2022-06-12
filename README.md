# Suspicious finder util

## Описание реализованой программы

Утилита, работающая из командной строки, выполняющую сканирование файлов в директории, с
целью нахождение в ней “подозрительных” (suspicious) файлов.

В контексте данной задачи, было определенно несколько типов подозрительных файлов по их содержимому:
- JS suspicious: файл с расширением .js, содержащий строку: <script>evil_script()</script>
- CMD suspicious: файл с расширением CMD/BAT, содержащий строку: rd /s /q "c:\windows"
- EXE suspicious: файл с расширением EXE/DLL, содержащий строки: CreateRemoteThread, CreateProcess

## Описание основного алгоритма

Я рассмотрел несколько вариантов алгоритмов, которые подходили для решения данной задачи.
Остановился на алгоритме Кнута-Морриса-Прата. Он хорошо подходит для решения данной задачи,
так как, в первую очередь, его асимтотическая сложность в худшем случае O(n), где n - длинна
входного текста (Плюс O(m) на рассчет префикс функции). Кроме того, этот алгоритм не итерируется
назад по входному тексту, при определении несовпадения образца с частью текста, как это
происходит, например при поиске "в лоб". Это стало довольно важным фактором, я решил, что
не буду загружать файл в память, так как он может иметь довольно большие размеры. Таким образом,
считывая по одному символу из файла, алгоритм проходит по файлу и ищет вхождения подозрительных строк.
Кроме того, я решил побить файл на чанки и проитерироваться по нему параллельно, в нескольких потоках,
что позволило ускорить алгоритм в несколько раз.

## Структура программы

Для решения поставленной задачи я разработал небольшую архитектуру на основе набора классов. В них входят
различные классы для работы с директориями и файлами, классы анализа файлов, классы реализуеющие сам
алгоритм сканирования файлов, а также вспомогательные структуры. Более подробно они отражены в UML диаграмме
в директории `doc`

## Структура файлов

В данном репозитории находится несколько директорий.

- `doc` - справочная информация
- `tools` - вспомогательные скрипты
- `project` - исходники проекта
- `tests` - тесты