import { NavBar } from "./NavBar";

type Props = {
    children: React.ReactNode;
  };
  
  //TODO: make this more fancy
  export const Layout = ({ children }: Props) => {
    return (
      <>
        <NavBar/>
        {children}
      </>
    );
  };