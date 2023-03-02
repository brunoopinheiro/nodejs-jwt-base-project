const jwt = require('jsonwebtoken');
require('dotenv/config');
const { UserService } = require('../services');

/* Mesma chave privada que usamos para criptografar o token.
Agora, vamos usá-la para desrciptografá-lo.
Numa aplicação real, essa chave jamais ficaria hardcoded no código assim,
e muito menos de forma duplicada, mas aqui só estamos interessados em
ilustrar seu uso. */
const secret = process.env.JWT_SECRET;

module.exports = async (req, res, next) => {
  // Aquele token gerado anteriormente virá na requisição
  // através do header 'Authorization' em todas as rotas que sejam autenticadas.
  const token = req.header('Authorization');

  // Caso o token não seja informado, simplesmente retornamos código de status 401
  if (!token) return res.status(401).json({ error: 'Token não encontrado' });

  try {
    // Através do método verify, podemos validar e decodificar nosso JWT.
    const decoded = jwt.verify(token, secret);
    /*
      A variável decoded será um objeto equivalente ao seguinte:
      {
        data: {
          userId: 1
        },
        iat: 1656616422,
        exp: 1657221222,
      }

      Caso o token esteja expirado, a própria biblioteca irá retornar um erro,
      por isso não é necessário fazer validação do tempo.
      Caso esteja tudo certo, nós então usamos o serviço de usuário para obter
      seus dados atualizados.
    */

      const user = await UserService.getByUserId(decoded.data.userId);

      if (!user) return res.status(401).json({ message: 'Erro ao procurar usuário do token' });

      req.user = user;

      next();
  } catch (e) {
    return res.status(401).json({ message: e.message });
  }
};
