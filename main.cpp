#include"Injector.h"



int main(void) {
	Injector injector(L"C:\\Users\\a2879\\Desktop\\��ʾ\\messagebox.dll");
	if (!injector.setPrivilege())
		std::cerr << "Ȩ������ʧ��" << std::endl;
	while (TRUE) {
		try
		{
			std::string mode;
			std::cin >> mode;
			if (mode == "inject")
				injector.inject();
			if (mode == "eject")
				injector.eject();
		}
		catch (const std::runtime_error& e) {
			std::cerr << "�쳣�� " << e.what() << std::endl;
		}
	}


}