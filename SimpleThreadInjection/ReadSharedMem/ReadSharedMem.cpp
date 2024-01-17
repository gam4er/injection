// ReadSharedMem.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <windows.h>

int main()
{
    HANDLE hMapFile = OpenFileMapping(/*FILE_MAP_EXECUTE PAGE_EXECUTE_READ  FILE_MAP_ALL_ACCESS*/ FILE_MAP_READ | FILE_MAP_WRITE | 0x0008, FALSE, L"SharedMemory");
    if (hMapFile == NULL) return 1;
    printf("FileMapping opened\n");
    // Проецирование разделяемой памяти в адресное пространство текущего процесса
    LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE /* | FILE_MAP_ALL_ACCESS*/, 0, 0, 1024);
    if (pBuf == NULL) {
        DWORD err = GetLastError();
        printf("Error code: %d\n", err);
        CloseHandle(hMapFile);
        return 1;
    }
    printf("Buf mapped\n");

    // Создание потока для выполнения шеллкода
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pBuf, NULL, 0, &threadID);
    if (hThread == NULL) {
        UnmapViewOfFile(pBuf);
        CloseHandle(hMapFile);
        return 1;
    }
    printf("Thread Created\n");

    // Ожидание завершения потока

    WaitForSingleObject(hThread, INFINITE);


    printf("Thread finished\n");

    // Освобождение ресурсов
    CloseHandle(hThread);
    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile);
    return 0;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
