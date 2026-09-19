# AlertaURL OSINT

**Analiza, verifica y reporta enlaces sospechosos.**

Aplicación web educativa para analizar una URL, consultar si ya fue reportada y alertar a la comunidad sobre posibles fraudes, phishing o suplantaciones digitales.

## Funciones

- Análisis guiado de URL, dominio, DNS, antigüedad y HTTPS.
- Seguimiento controlado de redirecciones y cambios de dominio.
- Detección orientativa de formularios sensibles, ventanas emergentes, marcas suplantadas y categorías de riesgo.
- Reportes comunitarios persistentes con prevención de duplicados.
- Informes técnicos ampliables, copiables y descargables.
- Carrusel de alertas con fecha, hora y valoración comunitaria.
- Aplicación web progresiva (PWA) instalable.
- Páginas de Privacidad, Términos y Créditos.

## Arquitectura y despliegue

El cliente está en `dist/client`, el Worker compatible con Cloudflare en `dist/server/index.js` y la migración de D1 en `drizzle`. La aplicación necesita un runtime de Workers y una base D1 para conservar reportes y valoraciones.

GitHub Pages puede publicar únicamente el cliente estático: por sí solo no ejecuta el Worker ni D1. Para mantener todas las funciones, despliega el proyecto en una plataforma compatible con Cloudflare Workers y dirige el dominio a ese despliegue.

## Uso responsable

Los resultados son educativos y orientativos. No certifican legitimidad, fraude o ilegalidad. Confirma siempre la entidad por un canal oficial y no introduzcas contraseñas, códigos, tarjetas ni documentos personales.

## Créditos y atribución

**Una herramienta educativa de [Educa OSINT](https://www.instagram.com/educaosint/)**  
Aprende inteligencia de fuentes abiertas.

Diseñado y creado por [**Josias Pool · @josiaspool**](https://www.instagram.com/josiaspool/).

Al reutilizar o distribuir el proyecto, conserva `LICENSE`, `NOTICE` y esta sección de créditos.

## Licencia

MIT. Consulta [LICENSE](LICENSE) y [NOTICE](NOTICE).
