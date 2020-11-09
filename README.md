# Teoria de las comunicaciones - TP3: Port Scanning

Detección del estado de los puertos en un sistema operativo sobre los protocolos de transporte
más usados del modelo de Internet: TCP y UDP.

## Setup

1. Usar Python v3 - (version manager: https://github.com/pyenv/pyenv)

  ```
  pyenv global v3.8.5
  ```

2. Instalar dependencias

  ```
  pip install -r requirements.txt
  ```


## Correr

Para correr el Port Scanner

```
python main.py IP
```

Resultados en `./scanned-responses-IP.csv`

## Experimentación

Para ver la experimentación

```
jupyter notebook experimentacion.ipynb
```

1. Correr `main.py IP`
2. Cambiar `ip` en el primer bloque del notebook
3. Correr!
