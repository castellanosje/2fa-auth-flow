import { Request, Response } from "express";
import { User } from "../schema/user.schema";


export const getUsers = async (req: Request, res: Response) => {
	
	console.log('user id->', req?.user?.id);

	try {

		const users = await User.find();

		return res.status(200).json(users);

	} catch (error) {

		if (error instanceof Error) {

			return res.status(500).json({ message: error.message });

		}
	}
};

export const updateUser = async (req: Request, res: Response) => {
    // tal vez sea mejor put ya que consultas repetitivas con los mismos datos crean nuevos eventos siempre
    // es decir no es indempotente
	try {

		const { id } = req.params;

        const updatedUser = await User.update({ id: parseInt(id) }, req.body);
		
		if (updatedUser?.affected){

            return res.status(200).json({message:`${updatedUser.affected} records affected`});

        }else{

            return res.status(304);

        }
			
	} catch (error) {

		if (error instanceof Error) {

			return res.status(500).json({ message: error.message });

		}
	}
};

