type User = {
    id:string;
    email?: string;
    userName?:string;
    firstName?:string;
	lastName?: string;
	active?: boolean;
	createdAt?: Date;
	updatedAt?: Date;
}

export default User;