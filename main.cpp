#include"Injector.h"



int main(void) {
	Injector injector(L"C:\\Users\\a2879\\Desktop\\演示\\messagebox.dll");
	if (!injector.setPrivilege())
		std::cerr << "权限提升失败" << std::endl;
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
			std::cerr << "异常： " << e.what() << std::endl;
		}
	}


}