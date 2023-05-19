# Estrategia de Puebas

## Objetivo
Identifiqué los requisitos del juego y revisé el código existente para comprender su estructura y funcionalidad.

## Enfoque de las pruebas 
Evaluar las partes de codigo erroneas para cumplir con los requisitos del juego, como el rango del número aleatorio, la cantidad de intentos y la validación del número ingresado por el jugador.

Se realizaron cambios en el código para obtener el rango del número aleatorio utilizando Math.floor(Math.random() * 100) + 1 y para establecer 10 intentos en lugar de 5.

Se agrego la validación del número ingresado por el jugador utilizando parseInt() y isNaN(). Esto aseguró que solo se consideraran números enteros válidos y se mostrara una alerta si se ingresaba otro tipo de valor.

Se realizaron correciones de sintaxis, ajustar los mensajes de victoria y derrota, y seleccionar correctamente los elementos del documento HTML mediante clases.

Verifiqué que el código modificado funcionara correctamente y cumpliera con los requisitos del juego.