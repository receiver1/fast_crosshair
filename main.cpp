
#include <windows.h>
#include <thread>

uint32_t originalAddress;

void timerHooked()
{
	// Переменная состояния инициализации
	static bool isInitializated{ false };
	if (!isInitializated)
	{
		// Получаем адрес модуля samp.dll в памяти процесса
		static uint32_t baseAddress = reinterpret_cast<uint32_t>(GetModuleHandle("samp.dll"));
		if (baseAddress)
		{
			// Получаем указатель на класс CInput
			class clInput* inputClass = *reinterpret_cast<class clInput**>(baseAddress + 0x21A0E8u);
			if (inputClass != nullptr)
			{
				// Создаём функцию для регистрации команд
				using CMDPROC = void(__cdecl*)(const char*);
				auto registerChatCommand
				{
					[&](const char* szCommand, CMDPROC cmdProc) -> void
					{
						reinterpret_cast<void(__thiscall*)(clInput*, const char*, CMDPROC)>
							(baseAddress + 0x65AD0u)(inputClass, szCommand, cmdProc);
					}
				};

				// Регистрируем команду
				registerChatCommand("fastcrosshair", [](const char* szInput)
				{
					static bool fastCrosshair{ false };
					fastCrosshair = !fastCrosshair;

					uint32_t patchAddress{ 0x58E1D9u };
					unsigned long ulProtection;

					// Снимаем протекцию размером 1 байт
					VirtualProtect(LPVOID(patchAddress), 1, PAGE_READWRITE, &ulProtection);

					// Устанавливаем значение адресу в зависимости от состояния
					*reinterpret_cast<uint8_t*>(patchAddress) = fastCrosshair ? 0xEB : 0x74;

					// Восстанавливаем протекцию
					VirtualProtect(LPVOID(patchAddress), 1, ulProtection, &ulProtection);
				});

				isInitializated = true;
			}
		}
	}
	// Вызываем оригинальный CTimer::Update (0x561B10)
	reinterpret_cast<void(__cdecl*)()>(originalAddress)();
}

/*
*	В данной ситуации класс является точкой входа
*	Поскольку мы сразу же объявляем объект класса,
*	то при загрузке вызывается его конструктор
*/
class clEntry
{
	uint32_t hookAddress{ 0x53E968u },
		&relativeAddress{ *reinterpret_cast<uint32_t*>(hookAddress + 1) };
	unsigned long ulProtection;
public:
	clEntry()
	{
		// Снимаем протекцию размером 5 байт
		VirtualProtect(LPVOID(hookAddress), 5, PAGE_READWRITE, &ulProtection);

		// Сохраняем оригинал для вызова в хуке
		originalAddress = relativeAddress + hookAddress + 5;

		// Подменяем вызов CTimer::Update на свой
		relativeAddress = reinterpret_cast<uint32_t>(&timerHooked) - hookAddress - 5;

		// Восстанавливаем протекцию
		VirtualProtect(LPVOID(hookAddress), 5, ulProtection, &ulProtection);
	}
	~clEntry()
	{
		// Снимаем протекцию размером 5 байт
		VirtualProtect(LPVOID(hookAddress), 5, PAGE_READWRITE, &ulProtection);

		// Подменяем свой вызов на оригинал
		relativeAddress = *reinterpret_cast<uint32_t*>(originalAddress) - hookAddress - 5;

		// Восстанавливаем протекцию
		VirtualProtect(LPVOID(hookAddress), 5, ulProtection, &ulProtection);
	}
}
entry;
