# Signatures for Traffic
Консольная утилита генерации статистики для дампов сетевого трафика

## Навигация
- [Загрузка](#загрузка)
- [Сборка](#сборка)
- [Использование](#использование)


## Загрузка 
Все исходники последней версии распололожены на github 


```
git clone https://github.com/Jodode/sft_prj.git
```

## Сборка
Сборка осущевстляется с помощью CMake, версия 3.0+
```
cmake -DPCAP_ROOT=<npcapSDK_dir> -B <build_dir> sft_prj
cmake --build <build_dir>
```

## Использование
```
sft -f <path/to/file.pcap>

sft -f <path/to/file.pcap> -o <output_file.(csv,txt)>
```

##### Support *.pcap and *.pcapng file formats
