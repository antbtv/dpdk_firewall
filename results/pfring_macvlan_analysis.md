# Анализ: почему PF_RING снижает производительность на macvlan vepa интерфейсах

## Результаты измерений

Тесты проводились 2026-05-01, топология: hairpin 64B, ns_send → macvlan vepa (vns_send) → eno1 → RPi5 enP1p1s0 → eno1 → macvlan vepa (vns_recv) → ns_recv.

| Конфигурация | pkt/s (клиент) | Потери | Примечание |
|---|---|---|---|
| Без PF_RING (`use_pfring: False`) | 370,265 | 0.07% | результаты P12-01, 2026-04-27 |
| С PF_RING (`use_pfring: True`) | ~113,000–115,000 | 0.2–2.0% | измерено 2026-05-01 |

**Деградация с PF_RING: ×3.3 снижение throughput.**

## Топология и путь пакета

```
ns_send
  └─ vns_send (macvlan vepa на eno1)
       └─ eno1 (физический NIC, Intel I219)
            └─ [Ethernet кабель]
                 └─ RPi5 enP1p1s0 (bridge hairpin)
                      └─ [Ethernet кабель обратно]
                           └─ eno1
                                └─ vns_recv (macvlan vepa на eno1)
                                     └─ ns_recv
```

Ключевой факт: `vns_send` и `vns_recv` — **виртуальные** интерфейсы уровня ядра (macvlan), не физические NIC.

## Причины деградации

### 1. PF_RING не поддерживает kernel bypass для macvlan

PF_RING ускоряет приём и передачу пакетов, создавая прямой канал между NIC драйвером и пространством пользователя, минуя `sk_buff` аллокации и сетевой стек ядра. Это работает через **драйвер-специфичный ZC (Zero Copy) модуль** или через hook в `netif_receive_skb`.

Macvlan — это виртуальный интерфейс. Пакеты из `vns_send` поступают в ядро через обычный путь:

```
t-raf (user space)
  → PF_RING socket (kernel)
  → macvlan TX handler
  → eno1 (физический NIC driver)
  → wire
```

PF_RING не может обойти macvlan TX handler — он обязан пройти через него, так как macvlan является промежуточным слоем между сокетом и физическим NIC. В результате PF_RING добавляет слой своей обработки **поверх** стандартного пути, а не **вместо** него.

### 2. Отсутствие ZC-драйвера для macvlan

PF_RING Zero Copy (ZC) требует специального драйвера для физического NIC (например, `pf_ring_zc_e1000e` для Intel I219). Но даже если ZC-драйвер установлен для `eno1`, он недоступен для macvlan-интерфейса `vns_send`, поскольку ZC работает на уровне очередей физического NIC, а macvlan не экспонирует отдельные очереди.

### 3. Накладные расходы PF_RING на виртуальных интерфейсах

Когда PF_RING не может применить ZC или native mode, он работает в **fallback mode**: перехватывает пакеты через `pf_ring_skb_ring_insert()` внутри ядра. Это добавляет:
- копирование `sk_buff` в PF_RING ring buffer
- дополнительные блокировки ring buffer
- overhead при wake up пользовательского процесса

В результате fallback mode PF_RING медленнее стандартных raw sockets (`AF_PACKET SOCK_RAW`), которые t-raf использует без PF_RING.

### 4. lsmod подтверждает: нет ZC-пользователей

```
pf_ring  233472  0
```

Число `0` (use count) означает: ни один активный процесс не использует PF_RING в ZC-режиме. При ZC use count был бы ≥ 1 во время работы t-raf. Это подтверждает, что t-raf работал в fallback mode.

## Вывод

PF_RING эффективен только при прямом доступе к физическому NIC (ZC-режим или native mode). В нашей топологии трафик проходит через macvlan vepa, что делает ZC недоступным. PF_RING переходит в fallback mode, который добавляет overhead вместо ускорения.

**Для данной топологии правильный выбор — стандартные raw sockets (AF_PACKET), которые обеспечивают 370k pkt/s против 113k pkt/s с PF_RING.**
